Scheduled-task reliability fixes now reject replaying an already recorded one-time
occurrence, prevent stale Redis dispatch acknowledgements from hiding a new retry,
use the shared database clock for built-in maintenance cutoffs, report lost lease
heartbeats, and cleanly stop after a partial local worker startup failure.
Dense recurring misfires now coalesce without walking every missed occurrence, and
upload task deadlines use the same database clock as scheduled cleanup so node
clock skew cannot expire newly created uploads.
