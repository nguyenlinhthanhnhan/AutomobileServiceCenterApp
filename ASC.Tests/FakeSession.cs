using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ASC.Tests
{
    public class FakeSession:ISession
    {
        public bool IsAvailable => throw new NotImplementedException();
        public string Id => throw new NotImplementedException();
        public IEnumerable<string> Keys => throw new NotImplementedException();

        private Dictionary<string, byte[]> _sessionFactory = new();

        public void Clear() => throw new NotImplementedException();

        public void Remove(string key) => throw new NotImplementedException();

        public void Set(string key, byte[] value)
        {
            if (!_sessionFactory.ContainsKey(key)) _sessionFactory.Add(key, value);
            else _sessionFactory[key] = value;
        }

        public bool TryGetValue(string key, out byte[] value)
        {
            if(_sessionFactory.ContainsKey(key) && _sessionFactory[key] != null)
            {
                value = _sessionFactory[key];
                return true;
            }
            else
            {
                value = null;
                return false;
            }
        }

        public Task LoadAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();

        public Task CommitAsync(CancellationToken cancellationToken = default) => throw new NotImplementedException();
    }
}
