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

RSADecrypter rsa = new RSADecrypter();

Guid guid = new Guid();

// Generate and serialize PublicKey
StringWriter sw = new StringWriter();
XmlSerializer xs = new XmlSerializer(typeof(RSAParameters));
xs.Serialize(sw, rsa.Generate(guid));
// Send publicKey to client
writer.WriteLine(sw.ToString());
string asymmetricInput = reader.ReadLine();

// Get Symmetric key from client
byte[] symKey = Convert.FromBase64String(asymmetricInput);
rsa.SetSymmetricKey(rsa.sesKey.Id, symKey);
Console.WriteLine("Got the key! " + asymmetricInput);

// Asymmetric part is done, now we can decrypt text symmetricly
while (true)
{
    string input = "";
    while (input != null)
    {
        input = reader.ReadLine();

        string data = rsa.Decrypt(rsa.sesKey.SymmetricKey, Convert.FromBase64String(input));
        Console.WriteLine("Message from client: " + data);
        writer.WriteLine("Decrypted data from server: " + data);
    }
}