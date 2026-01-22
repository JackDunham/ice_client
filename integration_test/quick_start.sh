cd integration_test

# Start infrastructure
make infra

# Start Link clients (isolated, can't see each other)
make links

# Start exchange bridges (enables WAN relay)
make exchanges

# Or all at once:
make up

# Run automated tests:
make test

# Clean up:
make clean