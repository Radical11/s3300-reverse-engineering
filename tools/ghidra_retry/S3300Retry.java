// Focused retries retain the original failure and never modify firmware bytes.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import com.google.gson.*;
import java.nio.file.*;

public class S3300Retry extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3)throw new IllegalArgumentException("Expected export directory, address and timeout");
        Path output=Path.of(args[0]);String entry=args[1];int timeout=Integer.parseInt(args[2]);
        Gson gson=new Gson();
        JsonObject original=JsonParser.parseString(Files.readString(output.resolve("functions").resolve(entry+".json"))).getAsJsonObject();
        Function function=getFunctionAt(toAddr(Long.parseUnsignedLong(entry,16)));
        if(function==null)throw new IllegalArgumentException("No existing native function at supplied entry");
        DecompInterface decompiler=new DecompInterface();decompiler.toggleCCode(true);decompiler.toggleSyntaxTree(true);
        if(!decompiler.openProgram(currentProgram))throw new IllegalStateException(decompiler.getLastMessage());
        JsonObject retry=original.deepCopy();
        retry.add("initial_decompilation",original.deepCopy());
        try {
            DecompileResults result=decompiler.decompileFunction(function,timeout,monitor);
            retry.addProperty("decompilation_completed",result.decompileCompleted());
            retry.addProperty("pseudocode",result.getDecompiledFunction()==null?null:result.getDecompiledFunction().getC());
            retry.addProperty("decompiler_message",result.getErrorMessage());
            retry.addProperty("retry_timeout_seconds",timeout);
        }finally{decompiler.dispose();}
        Path folder=output.resolve("retry-functions");Files.createDirectories(folder);
        Files.writeString(folder.resolve(entry+".json"),gson.toJson(retry)+"\n");
        println("S3300 focused retry "+entry+" complete="+retry.get("decompilation_completed"));
    }
}
