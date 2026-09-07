Track local scheduler and worker failures independently so a successful scheduler
poll cannot make health checks appear healthy while a worker is still failing.
