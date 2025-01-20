# Divisor

This is a simple program that creates a new network interface with several rotating IP addresses. It's specifically designed to work with Quotient.

Configuration is done through the .env file. The following variables are required:

- `REDIS_ADDR`: The address of the Quotient Redis server
- `REDIS_PASSWORD`: The password for the Quotient Redis server
- `NUM_IPS`: The number of IPs to create, usually equal to the number of Quotient Runners
- `DESIRED_SUBNET`: The subnet to use for the new interface
- `TARGET_SUBNETS`: A comma-separated list of subnets that will use the new interface