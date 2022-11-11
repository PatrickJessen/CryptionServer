using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace CryptionClient
{
    public class TCPServer
    {
        public event EventHandler ReceiveNewMessage;
        TcpClient client;
        NetworkStream stream;
        StreamReader reader;
        StreamWriter writer;
        public TCPServer()
        {
            client = new TcpClient();
        }
        public bool Connect(string ipaddress, int port)
        {
            client.Connect(ipaddress, port);
            stream = client.GetStream();
            reader = new StreamReader(stream);
            writer = new StreamWriter(stream) { AutoFlush = true };
            if (client.Connected)
            {
                if (null != ReceiveNewMessage)
                    ReceiveNewMessage(this, EventArgs.Empty);
                return true;
            }
            return false;
        }

        public void SendMessage(string message)
        {
            writer.WriteLine(message);
        }

        public string ReceiveMessage()
        {
            EventHandler handler = ReceiveNewMessage;
            if (handler != null)
            {
                ReceiveNewMessage(this, EventArgs.Empty);
            }
            return reader.ReadLine();
        }
    }
}
