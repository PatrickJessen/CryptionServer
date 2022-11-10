using System.Net.Sockets;
using System.Net;
using System.Text;

int port = 1234;
TcpListener listener = new TcpListener(IPAddress.Loopback, port);
listener.Start();

TcpClient client = listener.AcceptTcpClient();
NetworkStream stream = client.GetStream();
StreamWriter writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };
StreamReader reader = new StreamReader(stream, Encoding.ASCII);

while (true)
{
    string inputLine = "";
    while (inputLine != null)
    {
        inputLine = reader.ReadLine();
        writer.WriteLine("Echoing string: " + inputLine);
        Console.WriteLine("Echoing string: " + inputLine);
    }
    Console.WriteLine("Server saw disconnect from client.");
}