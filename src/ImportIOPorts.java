/* ###
 * Simple query for Symgrate.com.  If you use this, you owe EVM and Travis Goodspeed a tasty beer.
 * (No, a Jever doesn't count.)
 */
//Queries symgrate.com to a Thumb2 chip from its I/O Addresses.
//@category    Symgrate
//@author      Travis Goodspeed and EVM
//@menupath    Tools.Symgrate.Import IO Ports

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;

public class ImportIOPorts extends GhidraScript {
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();


    //Perform the HTTPS query.
    String queryjsvd(String model) throws InterruptedException, IOException {
        String requestURL = "https://symgrate.com/jsvd?"+model+"="+model;
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

    //Imports a chip from the JSON reply.
    void importchip(JsonElement arr){
        JsonArray obj=arr.getAsJsonArray();
        for(int i=0; i<obj.size(); i++){
            JsonElement el=obj.get(i);
            JsonObject guess=el.getAsJsonObject();
            Set<String> keys = guess.keySet();
            String pname=guess.get("PeripheralName").getAsString();
            String name=guess.get("Name").getAsString();
            long adr=guess.get("Adr").getAsLong();

            println(String.format("0x%08x %s.%s", adr, pname, name));
        }
    }

    //Imports a JSON string from the API query.
    void importresult(String json){
        Gson gson = new Gson();
        JsonObject obj = gson.fromJson(json, JsonObject.class);
        for(int i=0; i<obj.size(); i++){
            Set<String> keys = obj.keySet();
            for (String name : keys) {
                //importlabel(name, obj.getAsJsonObject(name));
                println("Got regs for "+name+".");
                importchip(obj.get(name));
            }

        }
    }

    @Override
    protected void run() throws Exception {
        String model=askString("Chip model number?", "Model");
        importresult(queryjsvd(model));
    }
}
