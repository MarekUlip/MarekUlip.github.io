function runModifyRowTests() {
        console.log("✅ Starting tests...");

        // Setup
        columns = ["Name", "Email"];
        data = [
            { Name: "Alice", Email: "alice@example.com" },
            { Name: "Bob", Email: "bob@example.com" }
        ];
        displayTable();

        // Test insertRow
        insertRow(0);
        console.assert(data.length === 3, "❌ insertRow should increase data length");
        console.assert(data[1].Name === "", "❌ insertRow should insert empty row");
        console.assert(data[2].Name === "Bob", "❌ Original row should shift correctly");
        console.log("✅ insertRow passed");

        // Test deleteRow
        deleteRow(1); // Deletes the inserted row
        console.assert(data.length === 2, "❌ deleteRow should decrease data length");
        console.assert(data[0].Name === "Alice", "❌ First row should remain unchanged");
        console.assert(data[1].Name === "Bob", "❌ Second row should be Bob after deletion");
        console.log("✅ deleteRow passed");

        // Test delete last row
        deleteRow(1);
        console.assert(data.length === 1, "❌ deleteRow should remove last row");
        console.assert(data[0].Name === "Alice", "❌ Remaining row should be Alice");
        console.log("✅ delete last row passed");

        console.log("✅ All tests completed successfully.");
    }