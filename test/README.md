# Notes about unit tests

Tests are most conveniently run using `ninja -C build test`. Some tests require
root privileges, see below.

## kmod - test libscsi-debug kernel module handling

Some tests require root privileges and are therefore skipped if the test is
run by an unprivileged user.

### Environment

 * `IOC_KMOD_TEST_MODULE=<module>`: Name of kernel module to test with. Defaults to
   `scsi_debug`. Note this must be a real *module name*, not an alias.
 * `IOC_KMOD_TEST_SKIP_SLOW=1`: Skip some of the longer-running tests.

## ioctest

This ist not an actual unit test, rather a "proof of concept" exectutable for
checking that libioc works. Run with `ioctest <block_device_path>`, specifying
a block device to be used for test I/O.
