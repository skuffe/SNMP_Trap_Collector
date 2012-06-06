using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
using System.ComponentModel;
using System.Globalization;
using SnmpSharpNet;
using System.Net.Sockets;
using System.Net;

namespace SNMP_Trap_Collector
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        private readonly BackgroundWorker _worker = new BackgroundWorker();
        private string currentVoltage;

        public MainWindow()
        {
            InitializeComponent();
            InitializeBackgroundWorker();
            _worker.RunWorkerAsync();
        }

        ///<summary>
        ///Initialization of background worker
        ///</summary>
        private void InitializeBackgroundWorker()
        {
            // Allow worker to report progress.
            this._worker.WorkerReportsProgress = true;
            // Allow cancellation of a running worker.
            this._worker.WorkerSupportsCancellation = true;
            // Add event handler for when RunWorkerAsync() is called - i.e. start of thread.
            this._worker.DoWork += new DoWorkEventHandler(worker_DoWork);
            // Add event handler for when a progress change occurs.
            this._worker.ProgressChanged += new ProgressChangedEventHandler(worker_ProgressChanged);
        }

        ///<summary>
        ///Actual work in backgroundworker thread
        ///</summary>
        private void worker_DoWork(object sender, DoWorkEventArgs e)
        {
            BackgroundWorker worker = sender as BackgroundWorker;

            // Construct a socket and bind it to the trap manager port 162 
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint ipep = new IPEndPoint(IPAddress.Any, 10162);
            EndPoint ep = (EndPoint)ipep;
            socket.Bind(ep);
            // Disable timeout processing. Just block until packet is received 
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 0);
            bool run = true;
            int inlen;
            int ver;
            while (run)
            {
                byte[] indata = new byte[16 * 1024];
                // 16KB receive buffer int inlen = 0;
                IPEndPoint peer = new IPEndPoint(IPAddress.Any, 0);
                EndPoint inep = (EndPoint)peer;
                try
                {
                    inlen = socket.ReceiveFrom(indata, ref inep);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception {0}", ex.Message);
                    inlen = -1;
                }
                if (inlen > 0)
                {
                    // Check protocol version int 
                    ver = SnmpPacket.GetProtocolVersion(indata, inlen);
                    if (ver == (int)SnmpVersion.Ver1)
                    {
                        // Parse SNMP Version 1 TRAP packet 
                        SnmpV1TrapPacket pkt = new SnmpV1TrapPacket();
                        pkt.decode(indata, inlen);
                        Console.WriteLine("** SNMP Version 1 TRAP received from {0}:", inep.ToString());
                        Console.WriteLine("*** Trap generic: {0}", pkt.Pdu.Generic);
                        Console.WriteLine("*** Trap specific: {0}", pkt.Pdu.Specific);
                        Console.WriteLine("*** Agent address: {0}", pkt.Pdu.AgentAddress.ToString());
                        Console.WriteLine("*** Timestamp: {0}", pkt.Pdu.TimeStamp.ToString());
                        Console.WriteLine("*** VarBind count: {0}", pkt.Pdu.VbList.Count);
                        Console.WriteLine("*** VarBind content:");
                        foreach (Vb v in pkt.Pdu.VbList)
                        {
                            Console.WriteLine("**** {0} {1}: {2}", v.Oid.ToString(), SnmpConstants.GetTypeName(v.Value.Type), v.Value.ToString());
                            string voltage = v.Value.ToString();
                            double max = 3.3;
                            string[] values = voltage.Split('V');
                            _worker.ReportProgress((int)Math.Floor((double)((double.Parse(values[0], CultureInfo.InvariantCulture) / max * 100))));
                            currentVoltage = voltage;
                        }
                        Console.WriteLine("** End of SNMP Version 1 TRAP data.");
                    }
                }
                else
                {
                    if (inlen == 0)
                        Console.WriteLine("Zero length packet received.");
                }
            }
            Yield(1000000);
        }

        ///<summary>
        ///Progress changed event
        ///</summary>
        private void worker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            this.label1.Content = currentVoltage;
            this.progressBar1.Value = e.ProgressPercentage;
        }

        private void Yield(long ticks)
        {
            // Note: a tick is 100 nanoseconds

            long dtEnd = DateTime.Now.AddTicks(ticks).Ticks;

            while (DateTime.Now.Ticks < dtEnd)
            {

                this.Dispatcher.Invoke(DispatcherPriority.Background, (DispatcherOperationCallback)delegate(object unused) { return null; }, null);

            }

        }
    }
}
