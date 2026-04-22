
/**
 * @name Network byte swap flows to memcpy
 * @description Traccia il flusso di dati dai macro network-to-host alla lunghezza di memcpy.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id cpp/uboot/network-to-memcpy-taint
 * @tags security
 * external/cwe/cwe-120
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import MyTaint::PathGraph


// Classe definita nello Step 9
class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
     mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)") and
     this = mi.getExpr()
    )
  }
}


module MyConfig implements DataFlow::ConfigSig {
 // Definiamo la SORGENTE: espressioni che appartengono alla nostra classe
 predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
}



 // Definiamo il SINK: il terzo argomento (indice 2) di una memcpy
 predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall call |
     call.getTarget().getName() = "memcpy" and
     sink.asExpr() = call.getArgument(2)
    )
  }
}

predicate isSanitizer(DataFlow::Node node) {
  exists(ComparisonOperation op |
    node.asExpr() = op.getAnOperand()
    )
}



module MyTaint = TaintTracking::Global<MyConfig>;



from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"

