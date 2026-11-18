using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

public class PBKDF2
{
    public static byte[] GenerateSalt()
    {
        using (var randomNumberGenerator = RandomNumberGenerator.Create())
        {
            var randomNumber = new byte[32];
            randomNumberGenerator.GetBytes(randomNumber);

            return randomNumber;
        }
    }

    public static byte[] HashPassword(
        byte[] toBeHashed,
        byte[] salt,
        int numberOfRounds,
        HashAlgorithmName hashAlgorithm,
        int hashByteLength)
    {
        if (hashAlgorithm == HashAlgorithmName.MD5)
        {
            using (var hmac = new HMACMD5(toBeHashed))
            {
                byte[] block = hmac.ComputeHash(salt);
                byte[] result = (byte[])block.Clone();

                for (int i = 1; i < numberOfRounds; i++)
                {
                    block = hmac.ComputeHash(block);
                    for (int j = 0; j < result.Length; j++)
                    {
                        result[j] ^= block[j];
                    }
                }
                return result;
            }
        }

        using (var rfc2898 = new Rfc2898DeriveBytes(
            toBeHashed,
            salt,
            numberOfRounds,
            hashAlgorithm))
        {
            return rfc2898.GetBytes(hashByteLength);
        }
    }
}

class Program
{
    private static long HashPassword(
        string passwordToHash,
        int numberOfRounds,
        HashAlgorithmName hashAlgorithm,
        int hashByteLength,
        bool printDetails)
    {
        var sw = new Stopwatch();

        sw.Start();

        var hashedPassword = PBKDF2.HashPassword(
            Encoding.UTF8.GetBytes(passwordToHash),
            PBKDF2.GenerateSalt(),
            numberOfRounds,
            hashAlgorithm,
            hashByteLength);

        sw.Stop();

        if (printDetails)
        {
            Console.WriteLine();
            Console.WriteLine("Password to hash : " + passwordToHash);
            Console.WriteLine("Hashed Password : " + Convert.ToBase64String(hashedPassword));
            Console.WriteLine("Iterations <" + numberOfRounds + "> Elapsed Time : " + sw.ElapsedMilliseconds + "ms");
        }

        return sw.ElapsedMilliseconds;
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        const string passwordToHash = "VeryComplexPassword";

        // 1. Демонстрація виводу за зразком книги (Figure 5-5, стор. 57-58)
        Console.WriteLine("=== Демонстрація роботи PBKDF2 (за зразком книги С. Хонтса) ===");
        HashPassword(passwordToHash, 70000, HashAlgorithmName.SHA256, 32, true);
        HashPassword(passwordToHash, 120000, HashAlgorithmName.SHA256, 32, true);
        HashPassword(passwordToHash, 170000, HashAlgorithmName.SHA256, 32, true);

        // 2. Таблиця замірів часу для Варіанта 7 (10 значень від 70 000 з кроком 50 000)
        const int variant = 7;
        int startIterations = variant * 10000; // 70 000
        int step = 50000;                      // крок 50 000

        Console.WriteLine($"\n=== Таблиця часу обчислення PBKDF2 для графіка (Варіант {variant}) ===");
        Console.WriteLine($"{"Ітерації",10} | {"MD5 (мс)",9} | {"SHA1 (мс)",9} | {"SHA256 (мс)",11} | {"SHA384 (мс)",11} | {"SHA512 (мс)",11}");
        Console.WriteLine(new string('-', 73));

        for (int i = 0; i < 10; i++)
        {
            int numberOfRounds = startIterations + (i * step);

            long tMd5    = HashPassword(passwordToHash, numberOfRounds, HashAlgorithmName.MD5, 16, false);
            long tSha1   = HashPassword(passwordToHash, numberOfRounds, HashAlgorithmName.SHA1, 20, false);
            long tSha256 = HashPassword(passwordToHash, numberOfRounds, HashAlgorithmName.SHA256, 32, false);
            long tSha384 = HashPassword(passwordToHash, numberOfRounds, HashAlgorithmName.SHA384, 48, false);
            long tSha512 = HashPassword(passwordToHash, numberOfRounds, HashAlgorithmName.SHA512, 64, false);

            Console.WriteLine($"{numberOfRounds,10} | {tMd5,9} | {tSha1,9} | {tSha256,11} | {tSha384,11} | {tSha512,11}");
        }
    }
}