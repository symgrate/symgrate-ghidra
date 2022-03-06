/* ###
 * Simple query for Symgrate.com.  If you use this, you owe EVM and Travis Goodspeed a tasty beer.
 * (No, a Jever doesn't count.)
 */
//Queries symgrate.com to recover Thumb2 function names.
//@category    Symgrate
//@menupath    Tools.Symgrate.NameFunctions



import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;

import static ghidra.program.model.symbol.SourceType.*;


public class NameFunctions extends GhidraScript{
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    //Perform the HTTPS query.
    String queryfns(String suffix) throws InterruptedException, IOException {
        String requestURL = "https://symgrate.com/jfns?"+suffix;
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


    //Imports one label, if the function isn't already named.
    void importlabel(String adr, JsonObject obj){
        String name=obj.get("Name").getAsString();
        Function f=getFunctionAt(toAddr(adr));

        //We're mostly trying to replace the DEFAULT entries.
        println(adr+": "+name);
        if(f.getSignatureSource()==DEFAULT){
            try {
                f.setName(name, IMPORTED);
            } catch (DuplicateNameException e) {
                println("Failed to import duplicate name: "+name+" at "+adr);
            } catch (InvalidInputException e) {
                e.printStackTrace();
            }
        }
    }

    //Imports a JSON string from the API query.
    void importresult(String json){
        Gson gson = new Gson();
        JsonObject obj = gson.fromJson(json, JsonObject.class);
        Set<String> keys = obj.keySet();
        for (String name : keys) {
            importlabel(name, obj.getAsJsonObject(name));
        }
    }

    String byteString(Function function) throws MemoryAccessException {
        //Grab eighteen bytes.
        byte[] bytes=getBytes(function.getEntryPoint(), 18);
        StringBuilder sb=new StringBuilder();
        for (byte aByte : bytes) {
            sb.append(String.format("%02x", ((int) aByte) & 0xFF));
        }
        return sb.toString();
    }

    @Override
    protected void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        int count = fm.getFunctionCount();
        monitor.initialize(count);
        Function f = getFirstFunction();
        StringBuilder q=new StringBuilder();

        for(int i=0; f!=null && !monitor.isCancelled(); i++){
            String adr=f.getEntryPoint().toString();
            String data=byteString(f);

            Function next=getFunctionAfter(f);
            if(f.getBody().getMaxAddress().getOffset()-f.getBody().getMinAddress().getOffset()>18){
                q.append(adr);
                q.append("=");
                q.append(data);
                q.append("&");
            }else {
                //println("Skipping short function at "+adr);
            }

            f=getFunctionAfter(f);

            if((i&0xFF)==0xFF || f==null){
                importresult(queryfns(q.toString()));
                q=new StringBuilder();
                monitor.setProgress(i);
            }
        }
        println("Symbol recovery complete.");
    }
}
