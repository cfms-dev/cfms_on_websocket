Make scheduled-execution completion and failure conditional on the current lease
owner and Provider generation, serialize aggregate transitions in one lock order,
and isolate every Redis scheduling resource by a required deployment namespace.
