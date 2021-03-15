using ASC.Business.Interfaces;
using ASC.DataAccess.Interfaces;
using ASC.Models.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASC.Business
{
    public class MasterDataOperations:IMasterDataOperations
    {
        private readonly IUnitOfWork _unitOfWork;
        public MasterDataOperations(IUnitOfWork unitOfWork) => _unitOfWork = unitOfWork;

        public async Task<List<MasterDataKey>> GetAllMasterKeysAsync()
        {
            var masterKeys = await _unitOfWork.Repository<MasterDataKey>().FindAllAsync();
            return masterKeys.ToList();
        }

        public async Task<List<MasterDataKey>> GetMasterKeyByNameAsync(string name)
        {
            var masterKeys = await _unitOfWork.Repository<MasterDataKey>().FindAllByPartitionKeyAsync(name);
            return masterKeys.ToList();
        }

        public async Task<bool> InsertMasterKeyAsync(MasterDataKey key)
        {
            using (_unitOfWork)
            {
                await _unitOfWork.Repository<MasterDataKey>().AddAsync(key);
                _unitOfWork.CommitTransaction();
                return true;
            }
        }

        public async Task<List<MasterDataValue>> GetAllMasterValuesByKeyAsync(string key)
        {
            var masterKeys = await _unitOfWork.Repository<MasterDataValue>().FindAllByPartitionKeyAsync(key);
            return masterKeys.ToList();
        }

        public async Task<MasterDataValue> GetMasterValueByNameAsync(string key, string name)
        {
            var masterValues = await _unitOfWork.Repository<MasterDataValue>().FindAsync(key, name);
            return masterValues;
        }

        public async Task<bool> InsertMasterValueAsync(MasterDataValue value)
        {
            using (_unitOfWork)
            {
                await _unitOfWork.Repository<MasterDataValue>().AddAsync(value);
                _unitOfWork.CommitTransaction();
                return true;
            }
        }

        public async Task<bool> UpdateMasterKeyAsync(string orginalPartitionKey, MasterDataKey key)
        {
            using (_unitOfWork)
            {
                // It alway return NULL in spite of PartitionKey, RowKey and Table although I seen have not anything wrong
                // var masterKey = await _unitOfWork.Repository<MasterDataKey>().FindAsync(originalPartitionKey, key.RowKey);
                var allDataTable = await _unitOfWork.Repository<MasterDataKey>().FindAllAsync();
                var masterKey = allDataTable.Where(x => x.PartitionKey.Equals(orginalPartitionKey) && x.RowKey.Equals(key.RowKey)).SingleOrDefault();
                masterKey.IsActive = key.IsActive;
                masterKey.IsDeleted = key.IsDeleted;
                masterKey.Name = key.Name;

                await _unitOfWork.Repository<MasterDataKey>().UpdateAsync(masterKey);
                _unitOfWork.CommitTransaction();
                return true;
            }
        }

        public async Task<bool> UpdateMasterValueAsync(string originalPartitionKey, string originalRowKey, MasterDataValue value)
        {
            using (_unitOfWork)
            {
                //var masterValue = await _unitOfWork.Repository<MasterDataValue>().FindAsync(originalPartitionKey, originalRowKey);
                var allDataTable = await _unitOfWork.Repository<MasterDataValue>().FindAllAsync();
                var masterValue = allDataTable.Where(x => x.PartitionKey.Equals(originalPartitionKey) && x.RowKey.Equals(originalRowKey)).SingleOrDefault();
                masterValue.IsActive = value.IsActive;
                masterValue.IsDeleted = value.IsDeleted;
                masterValue.Name = value.Name;

                await _unitOfWork.Repository<MasterDataValue>().UpdateAsync(masterValue);
                _unitOfWork.CommitTransaction();
                return true;
            }
        }

        public async Task<bool> UploadBulkMasterData(List<MasterDataValue> values)
        {
            using (_unitOfWork)
            {
                foreach (var value in values)
                {
                    // Find, if null insert MasterKey
                    var masterKey = await GetMasterKeyByNameAsync(value.PartitionKey);
                    if (!masterKey.Any())
                    {
                        await _unitOfWork.Repository<MasterDataKey>().AddAsync(new MasterDataKey()
                        {
                            Name = value.PartitionKey,
                            RowKey = Guid.NewGuid().ToString(),
                            PartitionKey = value.PartitionKey
                        });
                    }

                    // Find, if null Insert MasterValue
                    var masterValuesByKey = await GetAllMasterValuesByKeyAsync(value.PartitionKey);
                    var masterValue = masterValuesByKey.FirstOrDefault(p => p.Name == value.Name);
                    if (masterValue == null)
                    {
                        await _unitOfWork.Repository<MasterDataValue>().AddAsync(value);
                    }
                    else
                    {
                        masterValue.IsActive = value.IsActive;
                        masterValue.IsDeleted = value.IsDeleted;
                        masterValue.Name = value.Name;

                        await _unitOfWork.Repository<MasterDataValue>().UpdateAsync(masterValue);
                    }
                }

                _unitOfWork.CommitTransaction();
                return true;
            }
        }

        public async Task<List<MasterDataValue>> GetAllMasterValuesAsync()
        {
            var masterValues = await _unitOfWork.Repository<MasterDataValue>().FindAllAsync();
            return masterValues.ToList();
        }
    }
}
