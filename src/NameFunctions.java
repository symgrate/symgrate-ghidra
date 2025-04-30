/* ###
 * Simple query for Symgrate.com.  Updated with some options like dry running & picking a range
 * If you use this, you owe EVM and Travis Goodspeed a tasty beer.
 * (No, a Jever doesn't count.)
 */
//Queries symgrate.com to recover Thumb2 function names.
//@category    Symgrate
//@author      Travis Goodspeed and EVM
//@menupath    Tools.Symgrate.Name Functions

import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.address.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;

import static ghidra.program.model.symbol.SourceType.*;


public class NameFunctions extends GhidraScript {
  
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private boolean applyNames;
    private boolean printFilenames;
    private Address minAddress;
    private Address maxAddress;
    private String requestAddress;
    private String namePrefix;
    

    //Perform the HTTPS query.
    String queryjfns(String suffix) throws InterruptedException, IOException {

        String requestURL = requestAddress + "/jfns?" + suffix;
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

	//Modify the name if you want
	name = namePrefix + name;

        //We're mostly trying to replace the DEFAULT entries.
        if (printFilenames) {
          String filename = obj.get("Filename").getAsString();
          println(adr+": "+name +" (" + filename + ")");
        }
        else {
          println(adr+": "+name);
        }

	if (applyNames) {
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

    //Gets options from the user
    private void getUserInput() throws Exception {
               
        requestAddress = askString("Symgrate Options", "Symgrate Server Location", "https://symgrate.com:443");
        
        boolean useRange = askYesNo("Symgrate Options", "Use a range of addresses? (No to search whole program)");
        
        if (useRange) {
            minAddress = askAddress("Symgrate Options", "Starting address");
            maxAddress = askAddress("Symgrate Options", "Ending address");
        }
        else {
            minAddress = null;
            maxAddress = null;
        }
        
        String npAsk =askString("Symgrate Options", "Prefix to add to Symgrate labels (none adds no prefix)","none");
        if (npAsk.equals("none")) {
            namePrefix="";
        }
        else {
            namePrefix=npAsk;
        }
        applyNames = askYesNo("Symgrate Options", "Apply symbol names to DB? (No for a dry run)" );  
        printFilenames = askYesNo("Symgrate Options", "Print library filenames for matches?" );
    }



    @Override
    protected void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        int count = fm.getFunctionCount();
        monitor.initialize(count);
        Function f;
        StringBuilder q=new StringBuilder();
	AddressSet addressSet = null;	

	getUserInput();

	if (minAddress != null && maxAddress != null) {
            addressSet = new AddressSet(minAddress, maxAddress);
            f = fm.getFunctionContaining(minAddress);
            //they specified an address in the middle of a function, so skip to the next full function
            if (f.getEntryPoint() != minAddress) {
            	f = getFunctionAfter(f);
            }
        } else {
            f = getFirstFunction();
        }
        //Uncomment to debug
        //println("Starting at: " + f.getName() + " " + f.getEntryPoint().toString());

        for (int i = 0; f != null && !monitor.isCancelled(); i++) {
            if (addressSet != null && !addressSet.contains(f.getEntryPoint())) {
                break;
            }
            String adr=f.getEntryPoint().toString();
            String data=byteString(f);
            
            //Uncomment to debug
            //println("Scanning: " + f.getName() + " " + f.getEntryPoint().toString());

            if(f.getBody().getMaxAddress().getOffset()-f.getBody().getMinAddress().getOffset()>18){
                q.append(adr);
                q.append("=");
                q.append(data);
                q.append("&");
            }

            f=getFunctionAfter(f);
            
            if (addressSet != null && !addressSet.contains(f.getEntryPoint())) {
                f = null;
            }

            if((i&0xFF)==0xFF || f== null ){
                importresult(queryjfns(q.toString()));
                q=new StringBuilder();
                monitor.setProgress(i);
            }
        }
        println("Symbol recovery complete.");
    }
}
