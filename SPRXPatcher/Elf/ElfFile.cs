using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace SPRXPatcher.Elf;

public class ElfFile {
    public required ElfHeader Header;
    public required List<ElfProgramHeader> ProgramHeaders;
    public required List<ElfSectionHeader> SectionHeaders;

    public string SprxPath = "/dev_hdd0/tmp/plugin.sprx";

    private uint entrypointOffset;
    private uint entrypointAddress;
    private uint[] entrypointInstructions;
    private Dictionary<string, ElfSectionHeader> sectionHeaderLookup = new();

    [SetsRequiredMembers] public ElfFile(Stream stream) : this(new BigBinaryReader(stream)) { }

    [SetsRequiredMembers]
    public ElfFile(BigBinaryReader br) {
        this.Header = new ElfHeader(br);

        br.BaseStream.Seek((long) this.Header.ProgramHeaderOffset, SeekOrigin.Begin);
        this.ProgramHeaders = new List<ElfProgramHeader>(this.Header.ProgramHeaderCount);
        for (var i = 0; i < this.Header.ProgramHeaderCount; i++) this.ProgramHeaders.Add(new ElfProgramHeader(br));

        br.BaseStream.Seek((long) this.Header.SectionHeaderOffset, SeekOrigin.Begin);
        this.SectionHeaders = new List<ElfSectionHeader>(this.Header.SectionHeaderCount);
        for (var i = 0; i < this.Header.SectionHeaderCount; i++) this.SectionHeaders.Add(new ElfSectionHeader(br));

        // Read the sections
        foreach (var sectionHeader in this.SectionHeaders) {
            br.BaseStream.Seek((long) sectionHeader.PhysicalAddress, SeekOrigin.Begin);
            sectionHeader.Data = br.ReadBytes((int) sectionHeader.FileSize);
        }

        var section = this.SectionHeaders[this.Header.SectionHeaderStringIndex];
        foreach (var sectionHeader in this.SectionHeaders) {
            var name = section.Data![(int) sectionHeader.NameOffset..].TakeWhile(b => b != 0).ToArray();
            var nameStr = Encoding.ASCII.GetString(name);
            this.sectionHeaderLookup[nameStr] = sectionHeader;
        }

        // Find the entrypoint instruction
        var tocOffset = this.VirtualAddressToOffset(this.Header.Entry);
        br.BaseStream.Seek(tocOffset, SeekOrigin.Begin);
        Console.WriteLine($"TOC entry offset: 0x{tocOffset:X}");

        this.entrypointAddress = br.ReadUInt32();
        Console.WriteLine($"Entrypoint: 0x{this.entrypointAddress:X}");

        this.entrypointOffset = this.VirtualAddressToOffset(this.entrypointAddress);
        Console.WriteLine($"Entrypoint offset: 0x{this.entrypointOffset:X}");

        br.BaseStream.Seek(this.entrypointOffset, SeekOrigin.Begin);
        this.entrypointInstructions = new uint[4];
        for (var i = 0; i < 4; i++) {
            this.entrypointInstructions[i] = br.ReadUInt32();
        }
        Console.WriteLine(
            $"Entrypoint instructions: {string.Join(", ", this.entrypointInstructions.Select(i => $"0x{i:X}"))}");

        br.BaseStream.Seek(0, SeekOrigin.End);
    }

    private uint VirtualAddressToOffset(ulong virtualAddress) {
        var section = this.SectionHeaders.First(s =>
            s.VirtualAddress <= virtualAddress && virtualAddress < s.VirtualAddress + s.FileSize);
        var offset = virtualAddress - section.VirtualAddress;
        return (uint) (section.PhysicalAddress + offset);
    }

    public byte[] Write(Stream stream) {
        using var bw = new BigBinaryWriter(stream);
        return this.Write(bw);
    }

    public byte[] Write(BigBinaryWriter bw) {
        this.Header.Write(bw); // We'll go back and update the header later

        // Keep PHT at its original offset (right after ELF header). Stock PS3
        // appldr (non-CFW DEX, e.g. system 357 in DEX mode) rejects ELFs whose
        // PHT is relocated past the section data — see error 0x80010017.
        var originalPhtOffset = this.Header.ProgramHeaderOffset;
        var phtSize = (ulong) (this.Header.ProgramHeaderCount * 0x38);
        var phtEnd = originalPhtOffset + phtSize;
        {
            var currentOffset = (ulong) bw.BaseStream.Position;
            if (phtEnd > currentOffset) {
                var zeroes = new byte[phtEnd - currentOffset];
                Array.Fill(zeroes, (byte) 0);
                bw.Write(zeroes);
            }
        }

        // Write the sections
        foreach (var sectionHeader in this.SectionHeaders) this.WriteSection(sectionHeader, bw);

        // Place the shellcode inside the existing RX PT_LOAD's tail gap, so we
        // don't have to append a new (misaligned, VA!=PA) LOAD segment that
        // stock appldr would reject. The gap between the RX LOAD and the next
        // LOAD is ~0xbb18 bytes in both file and VA space — shellcode is tiny.
        var rxLoad = this.ProgramHeaders.First(p =>
            p.Type == ElfProgramHeader.ProgramType.Load &&
            (p.Flags & ElfProgramHeader.ProgramFlags.X) != 0);
        var nextLoad = this.ProgramHeaders
            .Where(p => p.Type == ElfProgramHeader.ProgramType.Load && p.Offset > rxLoad.Offset && p.FileSize > 0)
            .OrderBy(p => p.Offset)
            .FirstOrDefault();

        var customSectionOffset = this.Align(rxLoad.Offset + rxLoad.FileSize, 4);
        var customSectionVa = this.Align(rxLoad.VirtualAddress + rxLoad.FileSize, 4);
        Console.WriteLine($"Custom section VA: 0x{customSectionVa:X}, file offset: 0x{customSectionOffset:X}");

        var creator = new ShellcodeCreator();
        var (shellcode, newEntrypoint) = creator.Build(
            this.SprxPath,
            this.entrypointInstructions,
            this.entrypointAddress,
            (uint) customSectionVa
        );

        var shellcodeEndOffset = customSectionOffset + (ulong) shellcode.Length;
        if (nextLoad != null && shellcodeEndOffset > nextLoad.Offset)
            throw new InvalidOperationException(
                $"Shellcode (0x{shellcode.Length:X} bytes) does not fit in RX LOAD tail gap before next LOAD at 0x{nextLoad.Offset:X}");

        bw.BaseStream.Seek((long) customSectionOffset, SeekOrigin.Begin);
        bw.Write(shellcode);

        // Extend the RX PT_LOAD to cover the shellcode we just wrote in-place.
        var newRxEnd = shellcodeEndOffset;
        var growth = newRxEnd - (rxLoad.Offset + rxLoad.FileSize);
        rxLoad.FileSize += growth;
        rxLoad.MemorySize += growth;

        // Section header table goes at end of file. Don't add a custom section
        // header — PS3 PPU ELFs don't need it and skipping it keeps SHT count
        // unchanged.
        bw.BaseStream.Seek(0, SeekOrigin.End);
        var sectionHeaderOffset = bw.BaseStream.Position;
        foreach (var sectionHeader in this.SectionHeaders) sectionHeader.Write(bw);
        this.Header.SectionHeaderOffset = (ulong) sectionHeaderOffset;
        this.Header.SectionHeaderCount = (ushort) this.SectionHeaders.Count;

        // Rewrite the PHT in-place at its original offset (count is unchanged).
        bw.BaseStream.Seek((long) originalPhtOffset, SeekOrigin.Begin);
        foreach (var programHeader in this.ProgramHeaders) programHeader.Write(bw);
        this.Header.ProgramHeaderOffset = originalPhtOffset;
        this.Header.ProgramHeaderCount = (ushort) this.ProgramHeaders.Count;

        // Update the new entrypoint
        bw.BaseStream.Seek(this.entrypointOffset, SeekOrigin.Begin);
        foreach (var insn in newEntrypoint) bw.Write(insn);

        // Update the header with the program header offset
        bw.BaseStream.Seek(0, SeekOrigin.Begin);
        this.Header.Write(bw);

        var sha1 = SHA1.Create();
        using var hashMs = new MemoryStream();
        using var hashBw = new BigBinaryWriter(hashMs);
        void UpdateSha1(byte[] data) => hashBw.Write(data);

        foreach (var programHeader in this.ProgramHeaders) {
            var type = BitConverter.GetBytes((uint) programHeader.Type);
            var flags = BitConverter.GetBytes((uint) programHeader.Flags);
            Array.Reverse(type);
            Array.Reverse(flags);
            UpdateSha1(type);
            UpdateSha1(flags);

            if (programHeader.Type == ElfProgramHeader.ProgramType.Load && programHeader.MemorySize != 0) {
                var vaddr = BitConverter.GetBytes(programHeader.VirtualAddress);
                var memsz = BitConverter.GetBytes(programHeader.MemorySize);
                Array.Reverse(vaddr);
                Array.Reverse(memsz);
                UpdateSha1(vaddr);
                UpdateSha1(memsz);

                var br = new BigBinaryReader(bw.BaseStream);
                br.BaseStream.Seek((long) programHeader.Offset, SeekOrigin.Begin);
                var data = br.ReadBytes((int) programHeader.FileSize);
                UpdateSha1(data);
            }
        }

        bw.BaseStream.Seek(0, SeekOrigin.End);

        return sha1.ComputeHash(hashMs.ToArray());
    }

    private void SeekToAlignment(BigBinaryWriter bw, ulong alignment) {
        var currentOffset = (ulong) bw.BaseStream.Position;
        var alignedOffset = this.Align(currentOffset, alignment);

        if (alignedOffset > currentOffset) {
            var zeroes = new byte[alignedOffset - currentOffset];
            Array.Fill(zeroes, (byte) 0);
            bw.Write(zeroes);
        } else if (alignedOffset < currentOffset) {
            bw.BaseStream.Seek((long) alignedOffset, SeekOrigin.Begin);
        }
    }

    private ulong Align(ulong value, ulong alignment) => (value + alignment - 1) & ~(alignment - 1);

    private void WriteSection(ElfSectionHeader sectionHeader, BigBinaryWriter bw) {
        bw.BaseStream.Seek((long) sectionHeader.PhysicalAddress, SeekOrigin.Begin);

        // Write the section data
        if (sectionHeader.Data == null) throw new InvalidOperationException("Section data is null");
        bw.Write(sectionHeader.Data);
    }
}
