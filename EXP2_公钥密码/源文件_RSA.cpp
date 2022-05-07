#include <cstdio>
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <gmp.h>

#define KEY_LENGTH 2048 //公钥的长度
#define BASE 16         //输入输出的数字进制

using namespace std;

//定义结构体
struct key_pair
{
    char *n;
    char *d;
    int e;
};

//生成两个大素数
mpz_t *gen_primes()
{
    gmp_randstate_t grt;              //随机数生成
    gmp_randinit_default(grt);        //设置随机数生成算法为默认
    gmp_randseed_ui(grt, time(NULL)); //设置随机化种子为当前时间

    mpz_t key_p, key_q; //定义mpz_t类型变量
    mpz_init(key_p);
    mpz_init(key_q); //初始化，一个mpz_t类型的变量必须在初始化后才能被使用

    mpz_urandomb(key_p, grt, KEY_LENGTH / 2);
    mpz_urandomb(key_q, grt, KEY_LENGTH / 2); //随机生成两个大整数

    mpz_t *result = new mpz_t[2]; // new存储空间
    mpz_init(result[0]);
    mpz_init(result[1]);

    mpz_nextprime(result[0], key_p); //使用GMP自带的素数生成函数
    mpz_nextprime(result[1], key_q);

    mpz_clear(key_p); //释放占用的内存空间
    mpz_clear(key_q);

    return result; //返回生成的两个大素数
}

//生成密钥对
key_pair *gen_key_pair()
{
    //第一步：随机生成两个足够大的素数，p,q
    mpz_t *primes = gen_primes(); //调用自己定义的函数生成两个大素数

    //第二步：计算公共模数n，n=p*q
    mpz_t key_n, key_f; //定义并初始化变量
    mpz_init(key_n);
    mpz_init(key_f);
    mpz_mul(key_n, primes[0], primes[1]); //计算n，储存在key_n

    //第三步；计算欧拉函数：φ(n)=(p−1)∗(q−1)
    mpz_sub_ui(primes[0], primes[0], 1);  // p=p-1
    mpz_sub_ui(primes[1], primes[1], 1);  // q=q-1
    mpz_mul(key_f, primes[0], primes[1]); //计算欧拉函数，储存在key_f

    //第四步：选取一较小的与φ(n)互质的正整数e作为公共指数。
    //数对(n, e)则为密钥对中的公钥
    mpz_t key_e;
    mpz_init_set_ui(key_e, 65537); //初始化并设置e为65537
    // gmp_printf("%s (%ZX, %ZX)\n", "public key is:", key_n, key_e); //输出公钥(n, e)

    //第五步：计算数论倒数 d=e−1(modϕ(n))
    mpz_t key_d;
    mpz_init(key_d);
    mpz_invert(key_d, key_e, key_f); //求e的数论倒数d
    // gmp_printf("%s (%ZX, %ZX)\n", "private key is:", key_n, key_e); //输出私钥(n, d)

    key_pair *result = new key_pair;

    char *buf_n = new char[KEY_LENGTH + 10];
    char *buf_d = new char[KEY_LENGTH + 10];

    mpz_get_str(buf_n, BASE, key_n);
    result->n = buf_n;
    mpz_get_str(buf_d, BASE, key_d);
    result->d = buf_d;
    result->e = 65537;

    mpz_clear(primes[0]); //释放内存
    mpz_clear(primes[1]);
    mpz_clear(key_n);
    mpz_clear(key_d);
    mpz_clear(key_e);
    mpz_clear(key_f);
    delete[] primes;

    return result;
}

//加密函数
char *encrypt(const char *plain_text, const char *key_n, int key_e)
{
    mpz_t M, C, n;                         //定义并初始化变量
    mpz_init_set_str(M, plain_text, BASE); // M为明文
    mpz_init_set_str(n, key_n, BASE);      //(n, e)为公钥
    mpz_init_set_ui(C, 0);                 // C为密文

    mpz_powm_ui(C, M, key_e, n);              //使用GMP中模幂计算函数
    char *result = new char[KEY_LENGTH + 10]; // new一个空间
    mpz_get_str(result, BASE, C);             //把密文C转化为十六进制并储存到字符数组result中
    return result;                            //返回结果
}

//解密函数
char *decrypt(const char *cipher_text, const char *key_n, const char *key_d)
{
    mpz_t M, C, n, d;                       //定义并初始化变量
    mpz_init_set_str(C, cipher_text, BASE); // C为密文
    mpz_init_set_str(n, key_n, BASE);       //
    mpz_init_set_str(d, key_d, BASE);       //(n, d)为私钥
    mpz_init(M);                            // M为明文

    mpz_powm(M, C, d, n);                     //使用GMP中的模幂计算函数
    char *result = new char[KEY_LENGTH + 10]; // new一个空间
    mpz_get_str(result, BASE, M);             //把明文M转化为十六进制并储存到字符数组result中
    return result;                            //返回结果
}

int main()
{
    key_pair *p = gen_key_pair(); //生成密钥对

    cout << "n = " << p->n << endl; //输出公共模数n
    cout << "d = " << p->d << endl; //输出数论倒数d
    cout << "e = " << p->e << endl; //输出公共指数e

    char buf[KEY_LENGTH + 10];
    cout << "请输入要加密的数字，二进制长度不超过" << KEY_LENGTH << endl;
    cin >> buf; //以数字加密为例进行测试

    char *cipher_text = encrypt(buf, p->n, p->e);         //进行加密
    cout << "密文为：" << cipher_text << endl;
    char *plain_text = decrypt(cipher_text, p->n, p->d);  //进行解密
    cout << "明文为：" << plain_text << endl;

    if (strcmp(buf, plain_text) != 0)
        cout << "无法解密" << endl;
    else
        cout << "解密成功" << endl;

    return 0;
}
