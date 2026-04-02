use sea_orm::{EntityTrait, QuerySelect, Select};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PageRequest {
    pub page: u64,
    pub page_size: u64,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
        }
    }
}

impl PageRequest {
    pub fn normalized(&self) -> Self {
        let page = self.page.max(1);
        let page_size = self.page_size.clamp(1, 200);

        Self { page, page_size }
    }

    pub fn limit(&self) -> u64 {
        self.normalized().page_size
    }

    pub fn offset(&self) -> u64 {
        let normalized = self.normalized();
        (normalized.page - 1) * normalized.page_size
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SortSpec {
    pub field: String,
    pub direction: SortDirection,
}

pub fn apply_pagination<E>(query: Select<E>, page: &PageRequest) -> Select<E>
where
    E: EntityTrait,
{
    query.limit(page.limit()).offset(page.offset())
}
