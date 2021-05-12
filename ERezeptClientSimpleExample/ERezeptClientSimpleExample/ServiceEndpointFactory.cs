using System;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;

namespace ERezeptClientSimpleExample {
    public class ServiceEndpointFactory {
        private static readonly int Buffersize = 500000000;

        public static TPortClient CreateEndpoint<TPortClient, TPortType>(string url) where TPortClient : ClientBase<TPortType>, TPortType
            where TPortType : class {
            Binding binding;
            EndpointAddress endpointAddress = new EndpointAddress(url);

            if (url.StartsWith("https:")) {
                binding = new BasicHttpsBinding {
                    MaxBufferSize = Buffersize, MaxReceivedMessageSize = Buffersize,
                    ReaderQuotas = {MaxArrayLength = int.MaxValue, MaxDepth = int.MaxValue, MaxStringContentLength = int.MaxValue},
                    Security = new BasicHttpsSecurity {
                        Transport = new HttpTransportSecurity {
                            ClientCredentialType = HttpClientCredentialType.Certificate
                        }
                    }
                };
            } else {
                binding = new BasicHttpBinding {
                    MaxBufferSize = Buffersize, MaxReceivedMessageSize = Buffersize,
                    ReaderQuotas = {MaxArrayLength = int.MaxValue, MaxDepth = int.MaxValue, MaxStringContentLength = int.MaxValue}
                };
            }
            var client = (TPortClient) Activator.CreateInstance(typeof(TPortClient), binding, endpointAddress);
            client.Endpoint.Behaviors.Add(new LoggingEndpointBehavior());
            return client;
        }
    }

    public class LoggingEndpointBehavior : IEndpointBehavior {
        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters) {
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime) {
            clientRuntime.MessageInspectors.Add(new LoggingClientMessageInspector());
        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher) {
        }

        public void Validate(ServiceEndpoint endpoint) {
        }
    }

    public class LoggingClientMessageInspector : IClientMessageInspector {
        public void AfterReceiveReply(ref Message reply, object correlationState) {
            Console.Out.WriteLine($"Antwort {correlationState} Parameter {reply}");
        }

        public object BeforeSendRequest(ref Message request, IClientChannel channel) {
            var CallingInfo = Guid.NewGuid().ToString(); 
            Console.Out.WriteLine($"Aufruf {CallingInfo} Parameter {request}");
            return CallingInfo;
        }
    }
}