/* ###
 * Simple query for Symgrate.com.  If you use this, you owe EVM and Travis Goodspeed a tasty beer.
 * (No, a Jever doesn't count.)
 */
//Queries symgrate.com to a Thumb2 chip from its I/O Addresses.
//@category    Symgrate
//@author      Travis Goodspeed and EVM
//@menupath    Tools.Symgrate.Identify Chip

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Set;

public class IdentifyChip extends GhidraScript {
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    //Perform the HTTPS query.
    String queryjregs(String suffix) throws InterruptedException, IOException {
        String requestURL = "https://symgrate.com/jregs?"+suffix;
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(requestURL))
                .setHeader("User-Agent", "Ghidra "+getGhidraVersion()) // add request header
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        // print response headers
        HttpHeaders headers = response.headers();
        headers.map().forEach((k, v) -> System.out.println(k + ":" + v));

        return response.body();
    }

    //Imports a JSON string from the API query.
    void importresult(String json){
        Gson gson = new Gson();
        JsonArray obj = gson.fromJson(json, JsonArray.class);
        for(int i=0; i<obj.size(); i++){
            JsonElement el=obj.get(i);
            JsonObject guess=el.getAsJsonObject();
            Set<String> keys = guess.keySet();
            String name=guess.get("Name").toString();
            println(name);
        }
    }


    @Override
    protected void run() throws Exception {
        //Just for deduplication.
        HashMap<Long, String> hm= new HashMap<>();

        StringBuilder q=new StringBuilder();
        //Instruction instruction = getInstructionAt(getAddressFactory().getAddress("1fff1318"));
        Instruction instruction = getFirstInstruction();
        while(!monitor.isCancelled() && instruction!=null){
            String istr=instruction.toString();

            PcodeOp[] pop= instruction.getPcode();
            for (PcodeOp pcodeOp : pop) {
                //println(pop[i].getMnemonic());
                if (pcodeOp.getMnemonic().equals("COPY")) {
                    //Mostly finds inputs.
                    Address a = pcodeOp.getInput(0).getAddress();
                    Address b = pcodeOp.getOutput().getAddress();
                    if (a.isMemoryAddress()) {
                        //println(instruction.getAddress().toString());
                        long source = (currentProgram.getMemory().getInt(a));
                        if ((source & 0x0F0000000) == 0x040000000 && !hm.containsKey(source)) {
                            q.append(String.format("0x%x=r&", source));
                            hm.put(source,"Whatever");  //So we don't add the same port twice.
                        }
                    }
                    if (b.isMemoryAddress()) {
                        //println(a.toString());
                        long dest = (currentProgram.getMemory().getInt(b));
                        if ((dest & 0x0F0000000) == 0x040000000 && !hm.containsKey(dest)) {
                            q.append(String.format("0x%x=r&", dest));
                            hm.put(dest,"Whatever");  //So we don't add the same port twice.
                        }
                    }
                }
            }

            instruction = getInstructionAfter(instruction);
        }
        importresult(queryjregs(q.toString()));
    }
}
