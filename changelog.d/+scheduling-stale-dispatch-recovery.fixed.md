Redis scheduling now redelivers messages that were sent but never claimed before
the delivery timeout, preventing pending executions from becoming stranded.
