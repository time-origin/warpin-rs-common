use anyhow::{Result, anyhow};
use futures::future::BoxFuture;
use sea_orm::{DatabaseConnection, DatabaseTransaction, DbErr, TransactionTrait};

pub async fn run_in_transaction<T, F>(database: &DatabaseConnection, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: for<'txn> FnOnce(&'txn DatabaseTransaction) -> BoxFuture<'txn, Result<T>> + Send + 'static,
{
    database
        .transaction::<_, T, DbErr>(|txn| {
            Box::pin(async move {
                operation(txn)
                    .await
                    .map_err(|err| DbErr::Custom(err.to_string()))
            })
        })
        .await
        .map_err(|err| anyhow!(err))
}
