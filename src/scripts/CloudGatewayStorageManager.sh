#!/bin/bash

# Definitions

readonly SCRIPT_DIR=`dirname $0`
readonly ARGC="$#"
readonly ALLOW_ROOT="false"

# First, try to set up env

if [ -f "${SCRIPT_DIR}/CloudGateway_env.sh" ]; then
    . "${SCRIPT_DIR}/CloudGateway_env.sh"
else
    echo "Unable to find Cloud Gateway environment file, exiting." 1>&2
    exit 1
fi

# Check that we are not root

if [ "${EUID}" -eq 0 -a "${ALLOW_ROOT}" != 'true' ]; then
    print_error "Storage Manager should not be started as root."
    exit 1
fi

# Look for parameters

if [ "${ARGC}" -eq 1 ]; then
    readonly ACTION="$1"
    is_storage_manager_running
    readonly running=$?
    result=0

    case ${ACTION} in
	status)
	    if [ "${running}" -eq 0 ]; then
		echo "Storage Manager is NOT running."
	    else
		echo "Storage Manager is running."
	    fi
	    ;;
	start)
	    if [ "${running}" -eq 0 ]; then
                start_storage_manager
                result=$?

                if [ "${result}" -eq 0 ]; then
	            echo "Storage Manager started."
                else
	            print_error "Storage Manager failed to start with ${result}."
	            exit ${result}
                fi
	    else
		print_error "Storage Manager is already running."
		exit 1
	    fi
	    ;;
	force-stop)
	    if [ "${running}" -eq 1 ]; then
                stop_storage_manager

		if [ "${result}" -eq 0 ]; then
		    echo "Storage Manager stopped."
		else
		    print_error "Error ${result} while stopping Storage Manager."
		    exit ${result}
		fi
	    else
		print_error "Storage Manager is not running."
		exit 1
	    fi
	    ;;
	stop)
            # No fall through in bash 3.0
	    if [ "${running}" -eq 1 ]; then
                stop_storage_manager_gracefully

		if [ "${result}" -eq 0 ]; then
		    echo "Storage Manager stopped."
		else
		    print_error "Error ${result} while stopping Storage Manager."
		    exit ${result}
		fi
	    else
		print_error "Storage Manager is not running."
		exit 1
	    fi
	    ;;
	graceful-stop)
	    if [ "${running}" -eq 1 ]; then
                stop_storage_manager_gracefully

		if [ "${result}" -eq 0 ]; then
		    echo "Storage Manager stopped."
		else
		    print_error "Error ${result} while stopping Storage Manager."
		    exit ${result}
		fi
	    else
		print_error "Storage Manager is not running."
		exit 1
	    fi
	    ;;
        reload)
	    if [ "${running}" -eq 1 ]; then
                reload_storage_manager

		if [ "${result}" -eq 0 ]; then
		    echo "Storage Manager reloaded."
		else
		    print_error "Error ${result} while reloading Storage Manager."
		    exit ${result}
		fi
	    else
		print_error "Storage Manager is not running."
		exit 1
	    fi
	    ;;
        restart)
	    if [ "${running}" -eq 1 ]; then
                stop_storage_manager

		if [ "${result}" -eq 0 ]; then
		    echo "Storage Manager stopped."
		else
		    print_error "Error ${result} while stopping Storage Manager."
		    exit ${result}
		fi
	    fi

            start_storage_manager
            result=$?

            if [ "${result}" -eq 0 ]; then
	        echo "Storage Manager started."
            else
	        print_error "Storage Manager failed to start with ${result}."
	        exit ${result}
            fi
            ;;
	*)
	    print_error "Usage: $0 [start|stop|graceful-stop|force-stop|restart|reload|status]"
	    exit 1
    esac
else
    print_error "Usage: $0 [start|stop|graceful-stop|force-stop|restart|reload|status]"
    exit 1
fi
