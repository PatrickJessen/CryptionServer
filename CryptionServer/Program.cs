using System.Net.Sockets;
using System.Net;
using System.Text;
using CryptionServer;
using System.Xml.Serialization;
using System.Security.Cryptography;

int port = 1234;
TcpListener listener = new TcpListener(IPAddress.Loopback, port);
listener.Start();

TcpClient client = listener.AcceptTcpClient();
NetworkStream stream = client.GetStream();
StreamWriter writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };
StreamReader reader = new StreamReader(stream, Encoding.UTF8);

RSACrypter rsa = new RSACrypter();

rsa.GetPublicKey(reader.ReadLine());
Console.WriteLine("Got public key from client");

byte[] buffer = rsa.GenerateAndEncryptSessionKey();
writer.WriteLine(Convert.ToBase64String(buffer));

// Asymmetric part is done, now we can decrypt text symmetricly
while (true)
{
    string input = "";
    while (input != null)
    {
        input = reader.ReadLine();

        string decryptedData = rsa.Decrypt(rsa.sesKey.SymmetricKey, Convert.FromBase64String(input));
        byte[] Encrypt = rsa.EncryptData(rsa.sesKey.SymmetricKey, input);
        Console.WriteLine("Message from client: " + input);
        Console.WriteLine("Decrypted message: " + decryptedData);
        writer.WriteLine(Convert.ToBase64String(rsa.EncryptData(rsa.sesKey.SymmetricKey, "Decrypted data from server: " + decryptedData)));
    }
}