using ASC.DataAccess.Interfaces;
using Microsoft.Azure.Cosmos.Table;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.DataAccess
{
    public class UnitOfWork:IUnitOfWork
    {
        //private bool _disposed;
        private bool _complete;
        private Dictionary<string, object> _repositories;
        public Queue<Task<Action>> RollbackActions { get; set; }

        public string ConnectionString { get; set; }
        public UnitOfWork(string connectionString)
        {
            ConnectionString = connectionString;
            RollbackActions = new Queue<Task<Action>>();
        }
        public void CommitTransaction() => _complete = true;

        ~UnitOfWork() => Dispose(false);

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                try
                {
                    if (!_complete) RollbackTransaction();
                }
                finally
                {
                    RollbackActions.Clear();
                }
            }
            _complete = false;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void RollbackTransaction()
        {
            while (RollbackActions.Count > 0)
            {
                var undoAction = RollbackActions.Dequeue();
                undoAction.Result();
            }
        }

        public IRepository<T> Repository<T>() where T : TableEntity
        {
            if (_repositories is null) _repositories = new Dictionary<string, object>();

            var type = typeof(T).Name;

            if (_repositories.ContainsKey(type)) return (IRepository<T>)_repositories[type];

            var repositoryType = typeof(Repository<>);

            var repositoryInstance = Activator.CreateInstance(repositoryType.MakeGenericType(typeof(T)), this);

            _repositories.Add(type, repositoryInstance);

            return (IRepository<T>)_repositories[type];
        }
    }
}
