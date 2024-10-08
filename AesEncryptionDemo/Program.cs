// See https://aka.ms/new-console-template for more information
using AesEncryptionDemo;

var target = "asfsaf3rwgrgrsggrSSDSD33faff13r3fewg23fewddfdf31ffdfefewef13rthyjumum";
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("String for encryption: {0}", target);

AesEncryptionService aesEncryptionService = new AesEncryptionService("SomeDemoPasswordEncryption", "SomeDemoSaltEnctyption");
AesEncryptionRandomIVService aesEncryptionV2Service = new AesEncryptionRandomIVService("SomeDemoPasswordEncryption", "SomeDemoSaltEnctyption");
AuthenticatedEncryptionService authenticatedEncryptionService = new AuthenticatedEncryptionService("SomeDemoPasswordEncryption", "SomeDemoSaltEnctyption");

while (true)
{
    Console.WriteLine();
    var encrypted = await aesEncryptionService.EncryptString(target);
    var dectypted = await aesEncryptionService.DecryptString(encrypted);
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("Encrypted AesEncryptionService string: {0}", encrypted);
    Console.WriteLine("Decrypted AesEncryptionService string: {0}", dectypted);

    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("------------------------------------");

    Console.ForegroundColor = ConsoleColor.Magenta;
    var encryptedV2 = await aesEncryptionV2Service.EncryptString(target);
    var dectyptedV2 = await aesEncryptionV2Service.DecryptString(encryptedV2);
    Console.WriteLine("Encrypted AesEncryptionRandomIVService string: {0}", encryptedV2);
    Console.WriteLine("Decrypted AesEncryptionRandomIVService string: {0}", dectyptedV2);

    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("------------------------------------");

    Console.ForegroundColor = ConsoleColor.Blue;
    var encryptedV3 = authenticatedEncryptionService.Encrypt(target);
    var dectyptedV3 = authenticatedEncryptionService.Decrypt(encryptedV3);
    Console.WriteLine("Encrypted AuthenticatedEncryptionService string: {0}", encryptedV3);
    Console.WriteLine("Decrypted AuthenticatedEncryptionService string: {0}", dectyptedV3);

    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine();
    Console.WriteLine("Press Enter to exit. Any key for repeat.");
    if (Console.ReadKey().Key == ConsoleKey.Enter) { break; }
}