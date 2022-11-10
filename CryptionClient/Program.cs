using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CryptionClient;

int port = 1234;
TcpClient client = new TcpClient("localhost", port);
NetworkStream stream = client.GetStream();
StreamReader reader = new StreamReader(stream);
StreamWriter writer = new StreamWriter(stream) { AutoFlush = true };
RSAEncrypter rsa = new RSAEncrypter();


rsa.GetPublicKey(reader.ReadLine());
Console.WriteLine("Got public key from server");
byte[] test = rsa.GenerateAndEncryptSessionKey();
writer.WriteLine(Convert.ToBase64String(test));

while (true)
{
    Console.Write("Enter text: ");
    byte[] lineToSend = rsa.EncryptData(rsa.MySessionKey, Console.ReadLine());
    Console.WriteLine("Sending to server: " + Convert.ToBase64String(lineToSend));
    writer.WriteLine(Convert.ToBase64String(lineToSend));
    string lineReceived = reader.ReadLine();
    Console.WriteLine(lineReceived);
}