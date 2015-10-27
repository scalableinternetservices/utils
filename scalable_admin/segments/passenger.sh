# Start passenger
user_sudo passenger start -d --no-compile-runtime || error_exit 'Failed to start passenger'
