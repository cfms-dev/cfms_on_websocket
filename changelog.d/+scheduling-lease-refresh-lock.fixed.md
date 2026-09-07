Read the database clock only after acquiring the scheduled-execution lock during
lease refresh so lock contention cannot produce an already-expired renewed lease.
