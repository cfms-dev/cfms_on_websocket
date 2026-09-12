Close HTTP connections after rejecting a request for a forbidden subnet or an
oversized body, preventing unread request data from retaining concurrency slots.
