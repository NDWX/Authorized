using Xunit;

[assembly: TestCollectionOrderer( "Xunit.Extensions.Ordering.CollectionOrderer", "Xunit.Extensions.Ordering" )]
[assembly: TestCaseOrderer( "Xunit.Extensions.Ordering.TestCaseOrderer", "Xunit.Extensions.Ordering" )]