// Direct Ghidra observations. This script never executes target firmware.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class S3300Export extends GhidraScript {
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private void write(Path path,Object value) throws Exception {
        Path pending=path.resolveSibling(path.getFileName()+".partial");
        Files.writeString(pending,gson.toJson(value)+"\n",StandardCharsets.UTF_8);
        Files.move(pending,path,java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }
    private ArrayList<Object> ranges(AddressSetView body) {
        ArrayList<Object> rows=new ArrayList<>();
        for (AddressRange range:body.getAddressRanges()) rows.add(Map.of("start",range.getMinAddress().toString(),"end_inclusive",range.getMaxAddress().toString()));
        return rows;
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3) throw new IllegalArgumentException("Expected output, limit and priority address file");
        Path output=Path.of(args[0]); Files.createDirectories(output);
        int limit=Integer.parseInt(args[1]);
        Set<String> priorities=new LinkedHashSet<>(Files.readAllLines(Path.of(args[2])));
        Map<String,Object> image=new LinkedHashMap<>();
        image.put("evidence_class","direct Ghidra static analysis; not native REA Evidence");
        image.put("language",currentProgram.getLanguageID().toString());
        image.put("compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        image.put("image_base",currentProgram.getImageBase().toString());
        image.put("executable_sha256",currentProgram.getExecutableSHA256());
        ArrayList<Object> memory=new ArrayList<>();
        for(MemoryBlock block:currentProgram.getMemory().getBlocks()) {
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("name",block.getName());row.put("start",block.getStart().toString());row.put("size",block.getSize());
            row.put("read",block.isRead());row.put("write",block.isWrite());row.put("execute",block.isExecute());row.put("initialized",block.isInitialized());
            if(block.isInitialized() && block.getSize()<=64*1024*1024) {
                byte[] bytes=new byte[(int)block.getSize()];int count=block.getBytes(block.getStart(),bytes);
                row.put("read_bytes",count);row.put("sha256",hash(bytes));
            }
            memory.add(row);
        }
        image.put("memory",memory);
        ArrayList<Function> functions=new ArrayList<>();
        for(Function function:currentProgram.getFunctionManager().getFunctions(true)) functions.add(function);
        functions.sort(Comparator.comparingInt((Function f)->priorities.contains(f.getEntryPoint().toString())?0:1).thenComparing(f->f.getEntryPoint()));
        image.put("function_inventory_count",functions.size());
        write(output.resolve("image.json"),image);
        ArrayList<Object> inventory=new ArrayList<>();
        for(Function function:functions) inventory.add(Map.of("address",function.getEntryPoint().toString(),"name",function.getName(),"ranges",ranges(function.getBody())));
        write(output.resolve("inventory.json"),inventory);
        Path dossiers=output.resolve("functions");Files.createDirectories(dossiers);
        DecompInterface decompiler=new DecompInterface();
        decompiler.toggleCCode(true);decompiler.toggleSyntaxTree(true);
        if(!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
        int processed=0, reused=0, failed=0;
        try {
            BasicBlockModel model=new BasicBlockModel(currentProgram);
            for(Function function:functions) {
                monitor.checkCancelled();
                String entry=function.getEntryPoint().toString();Path file=dossiers.resolve(entry.replace(':','_')+".json");
                if(Files.exists(file)){reused++;continue;}
                if(limit>=0 && processed>=limit) break;
                Map<String,Object> row=new LinkedHashMap<>();
                row.put("address",entry);row.put("name",function.getName());row.put("ranges",ranges(function.getBody()));
                row.put("signature_inferred",function.getSignature().getPrototypeString());row.put("calling_convention_inferred",function.getCallingConventionName());
                ArrayList<Object> instructions=new ArrayList<>(),references=new ArrayList<>(),edges=new ArrayList<>();
                for(Instruction instruction:currentProgram.getListing().getInstructions(function.getBody(),true)) {
                    instructions.add(Map.of("address",instruction.getAddress().toString(),"bytes",HexFormat.of().formatHex(instruction.getBytes()),"text",instruction.toString()));
                    for(Reference ref:currentProgram.getReferenceManager().getReferencesFrom(instruction.getAddress())) {
                        Map<String,Object> reference=new LinkedHashMap<>();
                        reference.put("from",ref.getFromAddress().toString());reference.put("to",ref.getToAddress().toString());
                        reference.put("type",ref.getReferenceType().toString());reference.put("operand",ref.getOperandIndex());
                        references.add(reference);
                    }
                }
                row.put("instructions",instructions);row.put("references",references);
                ArrayList<String> callers=new ArrayList<>(),callees=new ArrayList<>();
                for(Function caller:function.getCallingFunctions(monitor)) callers.add(caller.getEntryPoint().toString());
                for(Function callee:function.getCalledFunctions(monitor)) callees.add(callee.getEntryPoint().toString());
                Collections.sort(callers);Collections.sort(callees);row.put("callers",callers);row.put("callees",callees);
                CodeBlockIterator blocks=model.getCodeBlocksContaining(function.getBody(),monitor);
                while(blocks.hasNext()) {
                    CodeBlock block=blocks.next();CodeBlockReferenceIterator successors=block.getDestinations(monitor);
                    while(successors.hasNext()) {
                        CodeBlockReference edge=successors.next();
                        edges.add(Map.of("from",block.getFirstStartAddress().toString(),"to",edge.getDestinationAddress().toString(),"flow",edge.getFlowType().toString()));
                    }
                }
                row.put("control_flow_edges",edges);
                try {
                    DecompileResults result=decompiler.decompileFunction(function,20,monitor);
                    row.put("decompilation_completed",result.decompileCompleted());
                    row.put("pseudocode",result.getDecompiledFunction()==null?null:result.getDecompiledFunction().getC());
                    row.put("decompiler_message",result.getErrorMessage());
                    if(!result.decompileCompleted())failed++;
                } catch(Exception failure) {row.put("decompilation_completed",false);row.put("decompiler_message",failure.toString());failed++;}
                write(file,row);processed++;
                if(processed%100==0) println("S3300 exported "+processed+" functions; reused="+reused+" failures="+failed);
            }
        } finally {decompiler.dispose();}
        write(output.resolve("export-summary.json"),Map.of("inventory",functions.size(),"processed_this_run",processed,"reused",reused,"failed_this_run",failed,"target_executed",false));
        println("S3300 export completed: processed="+processed+" reused="+reused+" failures="+failed);
    }
}
