using Microsoft.VisualBasic;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
//Copyright (C) 2011-2012 Artem Los, www.clizware.net.
//The author of this code shall get the credits

// This project uses two general algorithms:
//  - Artem's Information Storage Format (Artem's ISF-2)
//  - Artem's Serial Key Algorithm (Artem's SKA-2)

// A great thank to Iberna (https://www.codeplex.com/site/users/view/lberna)
// for getHardDiskSerial algorithm.

using System.Text;
using System.Management;
using System.Security;
using System.Numerics;


[assembly: AllowPartiallyTrustedCallers()]
namespace SKGL
{
    #region 序列号生成程序库
    #region 配置相关
    /// <summary>基本的配置抽象类</summary>
    public abstract class BaseConfiguration
    {
        //将所有的需要共享的函数、变量都放到这里，注意这个类必须继承后才能使用
        protected internal string _key = "";
        /// <summary>要存储的key</summary>
        public virtual string Key
        {
            //将随着生成和验证类的变化而变化
            get { return _key; }
            set { _key = value; }
        }

        /// <summary>机器码</summary>
        public virtual int MachineCode
        {

            get { return getMachineCode(); }
        }

        /// <summary>获取机器码的核心函数</summary>
        /// <returns></returns>
        [SecuritySafeCritical]
        private static int getMachineCode()
        {
            //      * Copyright (C) 2012 Artem Los, All rights reserved.
            //      * 
            //      * This code will generate a 5 digits long key, finger print, of the system
            //      * where this method is being executed. However, that might be changed in the
            //      * hash function "GetStableHash", by changing the amount of zeroes in
            //      * MUST_BE_LESS_OR_EQUAL_TO to the one you want to have. Ex 1000 will return 
            //      * 3 digits long hash.
            //      * 
            //      * Please note, that you might also adjust the order of these, but remember to
            //      * keep them there because as it is stated at 
            //      * (http://www.codeproject.com/Articles/17973/How-To-Get-Hardware-Information-CPU-ID-MainBoard-I)
            //      * the processorID might be the same at some machines, which will generate same
            //      * hashes for several machines.
            //      * 
            //      * The function will probably be implemented into SKGL Project at http://skgl.codeplex.com/
            //      * and Software Protector at http://softwareprotector.codeplex.com/, so I 
            //      * release this code under the same terms and conditions as stated here:
            //      * http://skgl.codeplex.com/license
            //      * 
            //      * Any questions, please contact me at
            //      *  * artem@artemlos.net
            //      
            methods m = new methods();

            ManagementObjectSearcher searcher = new ManagementObjectSearcher("select * from Win32_Processor");
            string collectedInfo = "";
            // here we will put the informa
            foreach (ManagementObject share in searcher.Get())
            {
                // first of all, the processorid
                collectedInfo += share.GetPropertyValue("ProcessorId");
            }

            searcher.Query = new ObjectQuery("select * from Win32_BIOS");
            foreach (ManagementObject share in searcher.Get())
            {
                //then, the serial number of BIOS
                collectedInfo += share.GetPropertyValue("SerialNumber");
            }

            searcher.Query = new ObjectQuery("select * from Win32_BaseBoard");
            foreach (ManagementObject share in searcher.Get())
            {
                //finally, the serial number of motherboard
                collectedInfo += share.GetPropertyValue("SerialNumber");
            }

            // patch luca bernardini
            if (string.IsNullOrEmpty(collectedInfo) | collectedInfo == "00" | collectedInfo.Length <= 3)
            {
                collectedInfo += getHddSerialNumber();
            }

            return m.getEightByteHash(collectedInfo, 100000);
        }

        // <summary>读取可引导分区的硬盘的序列号</summary>
        // <returns>如果失败，将返回String.Empty</returns>
        [SecuritySafeCritical]
        private static string getHddSerialNumber()
        {
            // --- Win32 Disk 
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("\\root\\cimv2", "select * from Win32_DiskPartition WHERE BootPartition=True");

            uint diskIndex = 999;
            foreach (ManagementObject partition in searcher.Get())
            {
                diskIndex = Convert.ToUInt32(partition.GetPropertyValue("Index"));
                break; // TODO: might not be correct. Was : Exit For
            }

            // I haven't found the bootable partition. Fail.
            if (diskIndex == 999)
                return string.Empty;
            
            // --- Win32 Disk Drive
            searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive where Index = " + diskIndex.ToString());

            string deviceName = "";
            foreach (ManagementObject wmi_HD in searcher.Get())
            {
                deviceName = wmi_HD.GetPropertyValue("Name").ToString();
                break; // TODO: might not be correct. Was : Exit For
            }


            // I haven't found the disk drive. Fail
            if (string.IsNullOrEmpty(deviceName.Trim()))
                return string.Empty;

            // -- Some problems in query parsing with backslash. Using like operator
            if (deviceName.StartsWith("\\\\.\\"))
            {
                deviceName = deviceName.Replace("\\\\.\\", "%");
            }


            // --- Physical Media
            searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMedia WHERE Tag like '" + deviceName + "'");
            string serial = string.Empty;
            foreach (ManagementObject wmi_HD in searcher.Get())
            {
                serial = wmi_HD.GetPropertyValue("SerialNumber").ToString();
                break; // TODO: might not be correct. Was : Exit For
            }

            return serial;

        }

    }

    /// <summary>序列号的配置</summary>
    public class SerialKeyConfiguration : BaseConfiguration
    {
        #region 变量
        private bool[] _Features = new bool[8] { //特征数组的默认值
		false,false,false,false,false,false,false,false};
        /// <summary>特征值</summary>
        public virtual bool[] Features
        {
            //will be changed in validating class.
            get { return _Features; }
            set { _Features = value; }
        }
        private bool _addSplitChar = true;
        public bool addSplitChar
        {
            get { return _addSplitChar; }
            set { _addSplitChar = value; }
        }
        #endregion
    }
    #endregion

    #region 生成序列号-加密部分
    /// <summary>生成序列号类</summary>
    public class Generate : BaseConfiguration
    {
        SerialKeyConfiguration skc = new SerialKeyConfiguration();
        methods m = new methods();
        Random r = new Random();
        public Generate() { }
        public Generate(SerialKeyConfiguration _serialKeyConfiguration)
        {
            skc = _serialKeyConfiguration;
        }
        private string _secretPhase;
        /// <summary>如果key是加密的，这里指密码</summary>
        public string secretPhase
        {
            get { return _secretPhase; }
            set
            {
                if (value != _secretPhase)
                {
                    _secretPhase = m.twentyfiveByteHash(value);
                }
            }
        }
        /// <summary>生成序列号的核心函数</summary>
        /// <param name="timeLeft">时间限制，例如 30 天.</param>
        public string doKey(int timeLeft)
        {
            return doKey(timeLeft, DateTime.Today);
        }
        /// <summary>生成序列号的核心函数</summary>
        /// <param name="timeLeft">时间限制，例如 30 天</param>
        /// <param name="useMachineCode">序列号对应特定的机器码, machine code是5位的long类型</param>
        public object doKey(int timeLeft, int useMachineCode)
        {
            return doKey(timeLeft, DateTime.Today, useMachineCode);
        }
        /// <summary>生成序列号的核心函数，可以改变创建日期</summary>
        /// <param name="timeLeft">时间限制，例如 30 天</param>
        /// <param name="creationDate">改变生成key的日期</param>
        /// <param name="useMachineCode">序列号对应特定的机器码, machine code是5位的long类型</param>
        public string doKey(int timeLeft, System.DateTime creationDate, int useMachineCode = 0)
        {
            if (timeLeft > 999)
            {
                //Checking if the timeleft is NOT larger than 999. It cannot be larger to match the key-length 20.
                throw new ArgumentException("The timeLeft is larger than 999. It can only consist of three digits.");
            }

            if (!string.IsNullOrEmpty(secretPhase) | secretPhase != null)
            {
                //if some kind of value is assigned to the variable "secretPhase", the code will execute it FIRST.
                //the secretPhase shall only consist of digits!
                System.Text.RegularExpressions.Regex reg = new System.Text.RegularExpressions.Regex("^\\d$");
                //cheking the string
                if (reg.IsMatch(secretPhase))
                {
                    //throwing new exception if the string contains non-numrical letters.
                    throw new ArgumentException("The secretPhase consist of non-numerical letters.");
                }
            }

            //if no exception is thown, do following
            string _stageThree = null;
            if (useMachineCode > 0 & useMachineCode <= 99999)
            {
                _stageThree = m._encrypt(timeLeft, skc.Features, secretPhase, useMachineCode, creationDate);
                // stage one
            }
            else
            {
                _stageThree = m._encrypt(timeLeft, skc.Features, secretPhase, r.Next(0, 99999), creationDate);
                // stage one
            }

            //if it is the same value as default, we do not need to mix chars. This step saves generation time.

            if (skc.addSplitChar == true)
            {
                // by default, a split character will be addedr
                Key = _stageThree.Substring(0, 5) + "-" + _stageThree.Substring(5, 5) + "-" + _stageThree.Substring(10, 5) + "-" + _stageThree.Substring(15, 5);
            }
            else
            {
                Key = _stageThree;
            }

            //we also include the key in the Key variable to make it possible for user to get his key without generating a new one.
            return Key;

        }        
    }
    #endregion

    #region 验证序列号-解密部分
    public class Validate : BaseConfiguration
    {
        SerialKeyConfiguration skc = new SerialKeyConfiguration();
        methods _a = new methods();
        public Validate() { }
        public Validate(SerialKeyConfiguration _serialKeyConfiguration)
        {
            skc = _serialKeyConfiguration;
        }
        /// <summary>y验证之前深入密钥key</summary>
        public string Key
        {
            get { return _key; }
            set
            {
                _res = "";
                _key = value;
            }
        }

        private string _secretPhase = "";
        /// <summary>
        /// If the key has been encrypted, when it was generated, please set the same secretPhase here.
        /// </summary>
        public string secretPhase
        {
            get { return _secretPhase; }
            set
            {
                if (value != _secretPhase)
                {
                    _secretPhase = _a.twentyfiveByteHash(value);
                }
            }
        }


        private string _res = "";

        private void decodeKeyToString()
        {
            // checking if the key already have been decoded.
            if (string.IsNullOrEmpty(_res) | _res == null)
            {

                string _stageOne = "";

                Key = Key.Replace("-", "");

                //if the admBlock has been changed, the getMixChars will be executed.
                _stageOne = Key;

                _stageOne = Key;

                if (!string.IsNullOrEmpty(secretPhase) | secretPhase != null)
                {
                    //if no value "secretPhase" given, the code will directly decrypt without using somekind of encryption
                    //if some kind of value is assigned to the variable "secretPhase", the code will execute it FIRST.
                    //the secretPhase shall only consist of digits!
                    System.Text.RegularExpressions.Regex reg = new System.Text.RegularExpressions.Regex("^\\d$");
                    //cheking the string
                    if (reg.IsMatch(secretPhase))
                    {
                        //throwing new exception if the string contains non-numrical letters.
                        throw new ArgumentException("The secretPhase consist of non-numerical letters.");
                    }
                }
                _res = _a._decrypt(_stageOne, secretPhase);
            }
        }
        private bool _IsValid()
        {
            //Dim _a As New methods ' is only here to provide the geteighthashcode method
            try
            {
                if (Key.Contains("-"))
                {
                    if (Key.Length != 23)
                    {
                        return false;
                    }
                }
                else
                {
                    if (Key.Length != 20)
                    {
                        return false;
                    }
                }
                decodeKeyToString();

                string _decodedHash = _res.Substring(0, 9);
                string _calculatedHash = _a.getEightByteHash(_res.Substring(9, 19)).ToString().Substring(0, 9);
                // changed Math.Abs(_res.Substring(0, 17).GetHashCode).ToString.Substring(0, 8)

                //When the hashcode is calculated, it cannot be taken for sure, 
                //that the same hash value will be generated.
                //learn more about this issue: http://msdn.microsoft.com/en-us/library/system.object.gethashcode.aspx
                if (_decodedHash == _calculatedHash)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception ex)
            {
                //if something goes wrong, for example, when decrypting, 
                //this function will return false, so that user knows that it is unvalid.
                //if the key is valid, there won't be any errors.
                return false;
            }
        }
        /// <summary>检查法key是否进行了修改,如果修改了，返回false,否则返回true</summary>
        public bool IsValid
        {
            get { return _IsValid(); }
        }
        private bool _IsExpired()
        {
            if (DaysLeft > 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        /// <summary>如果key过期，返回true,否则没有过期返回false</summary>
        public bool IsExpired
        {
            get { return _IsExpired(); }
        }
        private System.DateTime _CreationDay()
        {
            decodeKeyToString();
            System.DateTime _date = new System.DateTime();
            _date = new DateTime(Convert.ToInt32(_res.Substring(9, 4)), Convert.ToInt32(_res.Substring(13, 2)), Convert.ToInt32(_res.Substring(15, 2)));

            return _date;
        }
        /// <summary>返回key的创建日期</summary>
        public System.DateTime CreationDate
        {
            get { return _CreationDay(); }
        }
        private int _DaysLeft()
        {
            decodeKeyToString();
            int _setDays = SetTime;
            return Convert.ToInt32(((TimeSpan)(ExpireDate - DateTime.Today)).TotalDays); //or viseversa
        }
        /// <summary>返回key的有效日期</summary>
        public int DaysLeft
        {
            get { return _DaysLeft(); }
        }

        private int _SetTime()
        {
            decodeKeyToString();
            return Convert.ToInt32(_res.Substring(17, 3));
        }
        /// <summary>返回key生成后，实际的激活日期</summary>
        public int SetTime
        {
            get { return _SetTime(); }
        }
        private System.DateTime _ExpireDate()
        {
            decodeKeyToString();
            System.DateTime _date = new System.DateTime();
            _date = CreationDate;
            return _date.AddDays(SetTime);
        }
        /// <summary>返回key过期的日子</summary>
        public System.DateTime ExpireDate
        {
            get { return _ExpireDate(); }
        }
        private bool[] _Features()
        {
            decodeKeyToString();
            return _a.intToBoolean(Convert.ToInt32(_res.Substring(20, 3)));
        }
        /// <summary>返回8个特征值数组</summary>
        public bool[] Features
        {
            //we already have defined Features in the BaseConfiguration class. 
            //Here we only change it to Read Only.
            get { return _Features(); }
        }

        /// <summary>如果当前机器的机器码和key设置的机器码相同，返回true</summary>
        public bool IsOnRightMachine
        {
            get
            {
                int decodedMachineCode = Convert.ToInt32(_res.Substring(23, 5));

                return decodedMachineCode == MachineCode;
            }
        }
    }
    #endregion

    #region 核心方法
    internal class methods : SerialKeyConfiguration
    {

        //key的构造函数
        protected internal string _encrypt(int _days, bool[] _tfg, string _secretPhase, int ID, System.DateTime _creationDate)
        {
            // This function will store information in Artem's ISF-2
            //Random variable was moved because of the same key generation at the same time.
            int _retInt = Convert.ToInt32(_creationDate.ToString("yyyyMMdd"));
            // today
            decimal result = 0;
            result += _retInt;
            // adding the current date; the generation date; today.
            result *= 1000;
            // shifting three times at left

            result += _days;
            // adding time left
            result *= 1000;
            // shifting three times at left

            result += booleanToInt(_tfg);
            // adding features
            result *= 100000;
            //shifting three times at left

            result += ID;
            // adding random ID
            // This part of the function uses Artem's SKA-2
            if (string.IsNullOrEmpty(_secretPhase) | _secretPhase == null)
            {
                // if not password is set, return an unencrypted key
                return base10ToBase26((getEightByteHash(result.ToString())  +result.ToString()));
            }
            else
            {
                // if password is set, return an encrypted 
                return base10ToBase26((getEightByteHash(result.ToString()) + _encText(result.ToString(), _secretPhase) ));
            }
        }
        protected internal string _decrypt(string _key, string _secretPhase)
        {
            if (string.IsNullOrEmpty(_secretPhase) | _secretPhase == null)
            {
                // if not password is set, return an unencrypted key
                return base26ToBase10(_key);
            }
            else
            {
                // if password is set, return an encrypted 
                string usefulInformation = base26ToBase10(_key);
                return usefulInformation.Substring(0, 9) + _decText(usefulInformation.Substring(9), _secretPhase);
            }

        }

        //Deeper - encoding, decoding, et cetera.
        //Convertions, et cetera.----------------
        protected internal int booleanToInt(bool[] _booleanArray)
        {
            int _aVector = 0;
            //
            //In this function we are converting a binary value array to a int
            //A binary array can max contain 4 values.
            //Ex: new boolean(){1,1,1,1}

            for (int _i = 0; _i < _booleanArray.Length; _i++)
            {
                switch (_booleanArray[_i])
                {
                    case true:
                        _aVector += Convert.ToInt32((Math.Pow(2, (_booleanArray.Length - _i - 1))));
                        // times 1 has been removed
                        break;
                }
            }
            return _aVector;
        }
        protected internal bool[] intToBoolean(int _num)
        {
            //In this function we are converting an integer (created with privious function) to a binary array

            int _bReturn = Convert.ToInt32(Convert.ToString(_num, 2));
            string _aReturn = Return_Lenght(_bReturn.ToString(), 8);
            bool[] _cReturn = new bool[8];


            for (int i = 0; i <= 7; i++)
            {
                _cReturn[i] = _aReturn.ToString().Substring(i, 1) == "1" ? true : false;
            }
            return _cReturn;
        }
        protected internal string _encText(string _inputPhase, string _secretPhase)
        {
            //in this class we are encrypting the integer array.
            string _res = "";

            for (int i = 0; i <= _inputPhase.Length - 1; i++)
            {
                _res += modulo(Convert.ToInt32(_inputPhase.Substring(i, 1)) + Convert.ToInt32(_secretPhase.Substring(modulo(i, _secretPhase.Length), 1)), 10);
            }

            return _res;
        }
        protected internal string _decText(string _encryptedPhase, string _secretPhase)
        {
            //in this class we are decrypting the text encrypted with the function above.
            string _res = "";

            for (int i = 0; i <= _encryptedPhase.Length - 1; i++)
            {
                _res += modulo(Convert.ToInt32(_encryptedPhase.Substring(i, 1)) - Convert.ToInt32(_secretPhase.Substring(modulo(i, _secretPhase.Length), 1)), 10);
            }

            return _res;
        }
        protected internal string Return_Lenght(string Number, int Lenght)
        {
            // This function create 3 lenght char ex: 39 to 039
            if ((Number.ToString().Length != Lenght))
            {
                while (!(Number.ToString().Length == Lenght))
                {
                    Number = "0" + Number;
                }
            }
            return Number;
            //Return Number

        }
        protected internal int modulo(int _num, int _base)
        {
            // canged return type to integer.
            //this function simply calculates the "right modulo".
            //by using this function, there won't, hopefully be a negative
            //number in the result!
            return _num - _base * Convert.ToInt32(Math.Floor((decimal)_num / (decimal)_base));
        }
        protected internal string twentyfiveByteHash(string s)
        {
            int amountOfBlocks = s.Length / 5;
            string[] preHash = new string[amountOfBlocks + 1];

            if (s.Length <= 5)
            {
                //if the input string is shorter than 5, no need of blocks! 
                preHash[0] = getEightByteHash(s).ToString();
            }
            else if (s.Length > 5)
            {
                //if the input is more than 5, there is a need of dividing it into blocks.
                for (int i = 0; i <= amountOfBlocks - 2; i++)
                {
                    preHash[i] = getEightByteHash(s.Substring(i * 5, 5)).ToString();
                }

                preHash[preHash.Length - 2] = getEightByteHash(s.Substring((preHash.Length - 2) * 5, s.Length - (preHash.Length - 2) * 5)).ToString();
            }
            return string.Join("", preHash);
        }
        protected internal int getEightByteHash(string s, int MUST_BE_LESS_THAN = 1000000000)
        {
            //This function generates a eight byte hash

            //The length of the result might be changed to any length
            //just set the amount of zeroes in MUST_BE_LESS_THAN
            //to any length you want
            uint hash = 0;

            foreach (byte b in System.Text.Encoding.Unicode.GetBytes(s))
            {
                hash += b;
                hash += (hash << 10);
                hash ^= (hash >> 6);
            }

            hash += (hash << 3);
            hash ^= (hash >> 11);
            hash += (hash << 15);

            int result = (int)(hash % MUST_BE_LESS_THAN);
            int check = MUST_BE_LESS_THAN / result;

            if (check > 1)
            {
                result *= check;
            }

            return result;
        }
        protected internal string base10ToBase26(string s)
        {
            // This method is converting a base 10 number to base 26 number.
            // Remember that s is a decimal, and the size is limited. 
            // In order to get size, type Decimal.MaxValue.
            //
            // Note that this method will still work, even though you only 
            // can add, subtract numbers in range of 15 digits.
            char[] allowedLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();

            decimal num = Convert.ToDecimal(s);
            int reminder = 0;

            char[] result = new char[s.ToString().Length + 1];
            int j = 0;


            while ((num >= 26))
            {
                reminder = Convert.ToInt32(num % 26);
                result[j] = allowedLetters[reminder];
                num = (num - reminder) / 26;
                j += 1;
            }

            result[j] = allowedLetters[Convert.ToInt32(num)];
            // final calculation

            string returnNum = "";

            for (int k = j; k >= 0; k -= 1)  // not sure
            {
                returnNum += result[k];
            }
            return returnNum;

        }
        protected internal string base26ToBase10(string s)
        {
            // This function will convert a number that has been generated
            // with functin above, and get the actual number in decimal
            //
            // This function requieres Mega Math to work correctly.

            string allowedLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            System.Numerics.BigInteger result = new System.Numerics.BigInteger();


            for (int i = 0; i <= s.Length - 1; i += 1)
            {
                BigInteger pow = powof(26, (s.Length - i - 1));

                result = result + allowedLetters.IndexOf(s.Substring(i, 1)) * pow;

            }

            return result.ToString(); //not sure
        }

        protected internal BigInteger powof(int x, int y)
        {
            // Because of the uncertain answer using Math.Pow and ^, 
            // this function is here to solve that issue.
            // It is currently using the MegaMath library to calculate.
            BigInteger newNum = 1;

            if (y == 0)
            {
                return 1;
                // if 0, return 1, e.g. x^0 = 1 (mathematicaly proven!) 
            }
            else if (y == 1)
            {
                return x;
                // if 1, return x, which is the base, e.g. x^1 = x
            }
            else
            {
                for (int i = 0; i <= y - 1; i++)
                {
                    newNum = newNum * x;
                }
                return newNum;
                // if both conditions are not satisfied, this loop
                // will continue to y, which is the exponent.
            }
        }
    }
    #endregion

    #endregion
}