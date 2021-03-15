using ASC.DataAccess.Interfaces;
using ASC.Models.BaseTypes;
using ASC.Utilities;
using Microsoft.Azure.Cosmos.Table;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.DataAccess
{
    public class Repository<T> : IRepository<T> where T : TableEntity, new()
    {
        private readonly CloudStorageAccount storageAccount;
        private readonly CloudTableClient tableClient;
        private readonly CloudTable storageTable;

        public IUnitOfWork Scope { get; set; }

        public Repository(IUnitOfWork scope)
        {
            storageAccount = CloudStorageAccount.Parse(scope.ConnectionString);

            tableClient = storageAccount.CreateCloudTableClient();
            CloudTable table = tableClient.GetTableReference(typeof(T).Name);

            storageTable = table;
            Scope = scope;
        }

        private async Task<Action> CreateRollbackAction(TableOperation operation)
        {
            if (operation.OperationType == TableOperationType.Retrieve) return null;

            var tableEntity = operation.Entity;
            var cloudTable = storageTable;
            switch (operation.OperationType)
            {
                case TableOperationType.Insert:
                    return async () => await UndoInsertOperationAsync(cloudTable, tableEntity);
                case TableOperationType.Delete:
                    return async () => await UndoDeleteOperation(cloudTable, tableEntity);
                case TableOperationType.Replace:
                    var retrieveResult = await cloudTable.ExecuteAsync(TableOperation.Retrieve(tableEntity.PartitionKey,
                                                                                               tableEntity.RowKey));
                    return async () => await UndoReplaceOperation(cloudTable,
                                                                  retrieveResult.Result as DynamicTableEntity,
                                                                  tableEntity);
                default:
                    throw new InvalidOperationException("The storage operation cannot be identified");
            }
        }

        private async Task<Action> CreateRollbackAction(TableOperation operation, bool IsAuditOperation = false)
        {
            if (operation.OperationType == TableOperationType.Retrieve) return null;

            var tableEntity = operation.Entity;
            var cloudTable = !IsAuditOperation ? storageTable : tableClient.GetTableReference($"{typeof(T).Name}Audit");
            switch (operation.OperationType)
            {
                case TableOperationType.Insert:
                    return async () => await UndoInsertOperationAsync(cloudTable, tableEntity);
                case TableOperationType.Delete:
                    return async () => await UndoDeleteOperation(cloudTable, tableEntity);
                case TableOperationType.Replace:
                    var retrieveResult = await cloudTable.ExecuteAsync(TableOperation.Retrieve(tableEntity.PartitionKey, tableEntity.RowKey));
                    return async () => await UndoReplaceOperation(cloudTable, retrieveResult.Result as DynamicTableEntity, tableEntity);
                default:
                    throw new InvalidOperationException("The storage operation cannot be identified.");
            }
        }

        private async Task UndoInsertOperationAsync(CloudTable table, ITableEntity entity)
        {
            var deleteOperation = TableOperation.Delete(entity);
            await table.ExecuteAsync(deleteOperation);
        }

        private async Task UndoDeleteOperation(CloudTable table, ITableEntity entity)
        {
            var entityToRestore = entity as BaseEntity;
            entityToRestore.IsDeleted = false;

            var insertOperation = TableOperation.Replace(entity);
            await table.ExecuteAsync(insertOperation);
        }


        private async Task UndoReplaceOperation(CloudTable table, ITableEntity originalEntity, ITableEntity newEntity)
        {
            if (originalEntity != null)
            {
                if (!string.IsNullOrEmpty(newEntity.ETag)) originalEntity.ETag = newEntity.ETag;

                var replaceOperation = TableOperation.Replace(originalEntity);
                await table.ExecuteAsync(replaceOperation);
            }
        }

        private async Task<TableResult> ExecuteAsync(TableOperation operation)
        {
            var rollbackAction = CreateRollbackAction(operation);
            var result = await storageTable.ExecuteAsync(operation);
            Scope.RollbackActions.Enqueue(rollbackAction);

            // Audit Implementation
            if(operation.Entity is IAuditTracker)
            {
                // Make sure we do not use same RowKey and PartitionKey
                var auditEntity = ObjectExtensions.CopyObject<T>(operation.Entity);
                auditEntity.PartitionKey = $"{auditEntity.PartitionKey}-{auditEntity.RowKey}";
                auditEntity.RowKey = $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fff}";

                var auditOperation = TableOperation.Insert(auditEntity);
                var auditRollbackAction = CreateRollbackAction(auditOperation, true);

                var auditTable = tableClient.GetTableReference($"{typeof(T).Name}Audit");
                await auditTable.ExecuteAsync(auditOperation);

                Scope.RollbackActions.Enqueue(auditRollbackAction);
            }
            return result;
        }

        public async Task<T> AddAsync(T entity)
        {
            var entityToInsert = entity as BaseEntity;
            entityToInsert.CreatedDate = entityToInsert.UpdatedDate = DateTime.UtcNow.ToLocalTime();

            TableOperation insertOperation = TableOperation.Insert(entity);
            var result = await ExecuteAsync(insertOperation);
            return result.Result as T;
        }

        public async Task<T> UpdateAsync(T entity)
        {
            var entityToUpdate = entity as BaseEntity;
            entityToUpdate.UpdatedDate = DateTime.UtcNow.ToLocalTime();

            TableOperation updateOperation = TableOperation.Replace(entity);
            var result = await ExecuteAsync(updateOperation);
            return result.Result as T;
        }

        public async Task DeleteAsync(T entity)
        {
            var entityToDelete = entity as BaseEntity;
            entityToDelete.UpdatedDate = DateTime.UtcNow.ToLocalTime();

            TableOperation deleteOperation = TableOperation.Replace(entity);
            await ExecuteAsync(deleteOperation);
        }

        public async Task<T> FindAsync(string partitionKey, string rowKey)
        {
            TableOperation retrieveOperation = TableOperation.Retrieve<T>(partitionKey, rowKey);
            var result = await storageTable.ExecuteAsync(retrieveOperation);
            return result as T;
        }

        public async Task<IEnumerable<T>> FindAllByPartitionKeyAsync(string partitionKey)
        {
            TableQuery<T> query = new TableQuery<T>().Where(TableQuery.GenerateFilterCondition("PartitionKey",
                                                                                               QueryComparisons.Equal,
                                                                                               partitionKey));
            TableContinuationToken tableContinuationToken = null;
            var result = await storageTable.ExecuteQuerySegmentedAsync(query, tableContinuationToken);
            return result as IEnumerable<T>;
        }

        public async Task<IEnumerable<T>> FindAllAsync()
        {
            TableQuery<T> query = new();
            TableContinuationToken tableContinuationToken = null;
            var result = await storageTable.ExecuteQuerySegmentedAsync(query, tableContinuationToken);
            return result as IEnumerable<T>;
        }

        public async Task CreateTableAsync()
        {
            CloudTable table = tableClient.GetTableReference(typeof(T).Name);
            await table.CreateIfNotExistsAsync();

            if (typeof(IAuditTracker).IsAssignableFrom(typeof(T)))
            {
                var auditTable = tableClient.GetTableReference($"{typeof(T).Name}Audit");
                await auditTable.CreateIfNotExistsAsync();
            }
        }
    }
}
