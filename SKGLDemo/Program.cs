using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SKGL;

namespace SKGLDemo
{
    class Program
    {

        static void Main(string[] args)
        {
            Test2();
            Console.ReadKey();
        }

        static void Test1()
        {
            //1.创建key生成对象
            var CreateAKey = new Generate();
            //2.设置密钥
            CreateAKey.secretPhase = "testdemo";
            //3.生成key，30天时间限制
            var key1 = CreateAKey.doKey(30);
            //4.还可以设置机器码以及设置起始日期,机器码是1个5位Int数
            //机器码要客户在自己电脑上计算后获得，我这里是随便填一个
            var key2 = CreateAKey.doKey(30, 61123);
            Console.WriteLine("Key 1 :"+key1);
            Console.WriteLine("Key 2 :"+key2);
        }

        static void Test2()
        {
            //1.创建key验证对象
            var ValidateAKey = new Validate();
            //2.设置密钥
            ValidateAKey.secretPhase = "testdemo";
            //3.设置要验证的key，注意，这是上面代码生成的key1内容
            ValidateAKey.Key = "MFZIL-NSTBB-DLLXZ-RFHYV";           
            //4.直接验证是否被修改
            Console.WriteLine("Key 1 验证:{0}" , ValidateAKey.IsValid);
            //5.检查key是否过期，false说明在有效期内
            Console.WriteLine("Key 1 有效期:{0}", ValidateAKey.IsExpired);
            //同样验证Key2
            ValidateAKey.Key = "JPVFS-BLQOQ-FLFTN-HXLFW";
            //检查密钥是否被修改
            Console.WriteLine("Key 2 验证:{0}", ValidateAKey.IsValid);
            //我电脑的实际机器码是 61125，所以结果是不一样的
            Console.WriteLine("Key 2 是否和当前机器的机器码一样：{0}", ValidateAKey.IsOnRightMachine);
        }

        static void Test3()
        {
            //配置对象
            SerialKeyConfiguration skc = new SerialKeyConfiguration(); 
            //生成key对象
            Generate CreateAKey = new Generate(skc);
            //
            string trialKey = CreateAKey.doKey(30); //试用版30天期限
            //创建1个有时间限制的试用版
            skc.Features = new bool[8] { true, false, false, false,false, false,false ,false };
            // 当然这里的版本可以自定义，只要你自己认识就行了
        }

        static void Test4()
        {

        }
    }
}
