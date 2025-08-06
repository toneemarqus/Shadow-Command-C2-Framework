using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace C2Framework
{

    public class ConnectedOperator
    {
        public string OperatorId { get; set; }
        public string Username { get; set; }
        public string Role { get; set; }
        public IPEndPoint RemoteEndPoint { get; set; }
        public DateTime ConnectedAt { get; set; }
        public DateTime LastActivity { get; set; }
        public TcpClient Connection { get; set; }
        public NetworkStream BaseStream { get; set; }
        public SslStream SslStream { get; set; }
        public Stream ActiveStream { get; set; }
        public bool IsAuthenticated { get; set; }
        public string ActiveClientId { get; set; }
        public bool IsAlive { get; set; } = true;
        public bool IsEncrypted { get; set; } = false;
        public int LastKnownClientCount { get; set; } = -1;

        // TLS Properties
        public string TlsProtocol { get; set; }
        public string CipherAlgorithm { get; set; }
        public int CipherStrength { get; set; }

        // Synchronization for writes
        public readonly SemaphoreSlim WriteLock = new SemaphoreSlim(1, 1);

        // Connection status property for UI
        public string EncryptionStatus => IsEncrypted ? "🔒 TLS" : "🔓 Plain";
    }


    public enum OperatorMessageType
    {
        Authentication = 0,
        AuthResponse = 1,
        ClientList = 2,
        Command = 3,
        Response = 5,
        Notification = 6,
        Error = 7,
        OperatorJoin = 8,
        OperatorLeave = 9,
        ClientUpdate = 10,
        HeartBeat = 11,
        Chat = 12
    }

    public class OperatorMessage
    {
        public OperatorMessageType Type { get; set; }
        public string From { get; set; }
        public string To { get; set; }
        public string Data { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string ClientId { get; set; }
        public object Payload { get; set; }
        public string ColorHint { get; set; }

    }


}