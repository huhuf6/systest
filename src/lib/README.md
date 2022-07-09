# Test library design document

## High-level picture

    library process
    +----------------------------+
    | main                       |
    |  tst_run_tcases            |
    |   do_setup                 |
    |   for_each_variant         |
    |    for_each_filesystem     |   test process
    |     fork_testrun ------------->+--------------------------------------------+
    |      waitpid               |   | testrun                                    |
    |                            |   |  do_test_setup                             |
    |                            |   |   tst_test->setup                          |
    |                            |   |  run_tests                                 |
    |                            |   |   tst_test->test(i) or tst_test->test_all  |
    |                            |   |  do_test_cleanup                           |
    |                            |   |   tst_test->cleanup                        |
    |                            |   |  exit(0)                                   |
    |   do_exit                  |   +--------------------------------------------+
    |    do_cleanup              |
    |     exit(ret)              |
    +----------------------------+