Count recovered execution leases toward scheduled-task attempt limits so crashed
workers cannot cause task code to run beyond `max_attempts`.
