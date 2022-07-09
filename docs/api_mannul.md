主要数据结构

Strcut test

{

void (\*setup)(void);//测试初始化

void (\*cleanup)(void);//测试结束清理

void (\*test)(unsigned int test_nr); //测试函数 参数为测试次数

void (\*test_all)(void);

unsigned int tcnt; //测试次数

}

宏定义返回函数

#define tst_res(ttype, arg_fmt, \...) \\

    ({                                  \\

        TST_BUILD_BUG_ON(!((TTYPE_RESULT(ttype) ?: TCONF) & \\

            (TCONF \| TFAIL \| TINFO \| TPASS \| TWARN)));            
 \\

        tst_res\_(\_\_FILE\_\_, \_\_LINE\_\_, (ttype), (arg_fmt),
##\_\_VA_ARGS\_\_);\\

    })

返回类型

#define TTYPE_MASK  0x3f

#define TPASS   0   /\* Test passed flag \*/

#define TFAIL   1   /\* Test failed flag \*/

#define TBROK   2   /\* Test broken flag \*/

#define TWARN   4   /\* Test warning flag \*/

#define TINFO   16  /\* Test information flag \*/

#define TCONF   32  /\* Test not appropriate for configuration flag \*/

测试api

![](media/image1.png){width="5.981490594925634in"
height="3.9485312773403325in"}

Main() 测试程序入口

Tst_run_tcases 测试框架初始化

Fork_testrun fork子进程执行测试

Testrun 子进程执行测试初始化和清理

Runtests 执行自定义测试函数

Do_exit 测试结束，打印测试结果

Do_clean 清理测试框架

exit测试结束


C代码测试用例编写接口:
（1）	定义test_ret() 返回测试结果
（2）	定义测试返回结果种类
1.	pass
2.	fail
3.	tconf(配置错误)
（3）	set_up()初始化测试所需参数
（4）	用tst_test结构指定测试函数和测试初始化函数
（5）	定义测试用例实际函数入口tst_run_tcases(无返回值)实际入口点被包含在头文件中




Shell测试用例基本框架
shell代码测试用例编写接口
（1）	定义test_ret() 返回测试结果
（2）	定义test_run() 执行测试
（3）定义测试返回结果种类
1.pass
2.fail
3.tconf(配置错误)
