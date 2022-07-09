# C代码测试库设计

## High-level picture

    library process
    +----------------------------+
    | main                       |
    |  tst_run_tcases            |
    |   do_setup                 |测试库的准备
    |   for_each_variant         |测试的执行次数
    |    fork_testrun     |   test process
    |      waitpid           |   | testrun                                    |
    |                            |   |   tst_test->setup                      |测试执行前的准备
    |                            |   |   run_tests                                 |
    |                            |   |   tst_test->test(i) or tst_test->test_all  |
    |                            |   |   tst_test->cleanup                        |
    |                            |   |  exit(0)                                   |
    |   do_exit                  |   +--------------------------------------------+
    |    do_cleanup              |
    |     exit(ret)              |
    +----------------------------+

## 测试生命周期概述

执行测试时，首先我们检查执行各种测试前的先决条件。这些在 tst_test 结构和
范围从简单的 '.require_root' 到更复杂的内核 .config 布尔值表达式，
例如：“CONFIG_X86_INTEL_UMIP=y | CONFIG_X86_UMIP=y”。

在我们 fork() 测试具体用例前，测试库会设置一个超时警报并
也是心跳信号处理程序，并相应地设置alarm（2）测试超时。
当测试超时时，测试库获取 SIGALRM 和警报处理程序通过发送
 SIGKILL 到主进程。测试进程使用心跳处理程序来重置记时

完成后，使用 fork() 执行测试用例。首先是测试进程
重置信号处理程序并将其 pid 设置为进程组主进程，以便我们
如果需要，可以kill该进程组下的所有进程。测试库继续挂起
本身在 waitpid() 系统调用中并等待子进程完成。

测试进程继续并调用测试 setup() 函数（如存在）。
在我们fork进程之后，执行所有测试回调，这样可以使测试失败时测试库
进程不至于崩溃。在这种情况下fork_testrun() 函数退出，但上层循环
仍继续进行。

测试完成后，cleanup()进行对测试的清理
tst_brk() 处理程序也调用测试 cleanup() 以进行清理。
确保只清理已经设置的资源并以相反的顺序我们在 setup() 中执行的操作。

对于fork()出的相关孙子进程，由执行测试模块中的reap_function进行处理，杀死
孤儿进程

