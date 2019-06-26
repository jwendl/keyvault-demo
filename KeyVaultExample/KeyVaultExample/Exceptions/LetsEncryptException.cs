using System;

namespace KeyVaultExample.Exceptions
{
    public class LetsEncryptException
        : Exception
    {
        public LetsEncryptException(string message)
            : base(message)
        {

        }
    }
}
