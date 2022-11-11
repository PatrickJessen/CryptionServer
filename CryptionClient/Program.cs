using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;
using CryptionClient;

int port = 1234;
//TcpClient client = new TcpClient("localhost", port);
//NetworkStream stream = client.GetStream();
//StreamReader reader = new StreamReader(stream);
//StreamWriter writer = new StreamWriter(stream) { AutoFlush = true };
TCPServer server = new TCPServer();
server.Connect("localhost", port);
RSACrypter rsa = new RSACrypter();

StringWriter sw = new StringWriter();
XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));
xs.Serialize(sw, rsa.MySessionKey.PublicKey);
server.SendMessage(sw.ToString());

string asymmetricInput = server.ReceiveMessage();

byte[] symKey = Convert.FromBase64String(asymmetricInput);
rsa.SetSymmetricKey(symKey);
Console.WriteLine("Got the key! " + asymmetricInput);

while (true)
{
    Console.Write("Enter text: ");
    byte[] lineToSend = rsa.EncryptData(rsa.MySessionKey.SymmetricKey, Console.ReadLine());
    Console.WriteLine("Sending to server: " + Convert.ToBase64String(lineToSend));
    server.SendMessage(Convert.ToBase64String(lineToSend));
    string lineReceived = server.ReceiveMessage();
    Console.WriteLine(rsa.Decrypt(rsa.MySessionKey.SymmetricKey, Convert.FromBase64String(lineReceived)));
}