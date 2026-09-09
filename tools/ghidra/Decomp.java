// Decompile named or addressed functions and write the C to a file.
//
// Calibration for whether a decompiler earns its place here: every target below
// is a question already answered by hand or by measurement today, so the output
// can be checked rather than believed.
//
//   analyzeHeadless <proj> <name> -process <bin> -noanalysis \
//       -scriptPath <dir> -postScript Decomp.java <outfile> <addr|name> [...]
//
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class Decomp extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: Decomp <outfile> <addr-or-name> [more...]");
            return;
        }

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        // 300 s: WnmpDir_serviceField is ~43 KB and will not decompile quickly.
        int timeout = 300;

        PrintWriter out = new PrintWriter(args[0]);
        for (int i = 1; i < args.length; i++) {
            String target = args[i];
            Function f = findFunction(target);
            out.println("==================================================");
            if (f == null) {
                out.println("TARGET " + target + ": NO FUNCTION FOUND");
                println("no function for " + target);
                continue;
            }
            out.println("TARGET  " + target);
            out.println("NAME    " + f.getName());
            out.println("ENTRY   " + f.getEntryPoint());
            out.println("SIZE    " + f.getBody().getNumAddresses() + " bytes");
            out.println("--------------------------------------------------");
            DecompileResults r = di.decompileFunction(f, timeout, monitor);
            if (r != null && r.decompileCompleted()) {
                out.println(r.getDecompiledFunction().getC());
            } else {
                String e = (r == null) ? "null result" : r.getErrorMessage();
                out.println("DECOMPILATION FAILED: " + e);
                println("decompile failed for " + target + ": " + e);
            }
            out.flush();
        }
        out.close();
        di.dispose();
        println("wrote " + args[0]);
    }

    private Function findFunction(String target) {
        if (target.startsWith("0x")) {
            Address a = currentProgram.getAddressFactory()
                    .getAddress(target.substring(2));
            if (a == null) {
                return null;
            }
            Function f = getFunctionAt(a);
            return (f != null) ? f : getFunctionContaining(a);
        }
        return getGlobalFunctions(target).isEmpty()
                ? null : getGlobalFunctions(target).get(0);
    }
}
