// Caller-declared authenticated function entries, not Ghidra discoveries.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;

public class S3300Seed extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected a seed TSV");
        ArrayList<Long> entries = new ArrayList<>();
        for (String row : Files.readAllLines(Path.of(args[0]))) {
            if (!row.isBlank() && !row.startsWith("#")) entries.add(Long.parseUnsignedLong(row.split("\t")[0],16));
        }
        entries.sort(Comparator.reverseOrder());
        int created=0, existing=0, failed=0;
        for (long value : entries) {
            monitor.checkCancelled();
            Address address = toAddr(value);
            if (getFunctionAt(address)!=null) { existing++; continue; }
            if (currentProgram.getMemory().contains(address) && disassemble(address) && createFunction(address,"sub_"+Long.toHexString(value))!=null) created++;
            else failed++;
        }
        println("S3300 caller seeds: created="+created+" existing="+existing+" failed="+failed);
    }
}
