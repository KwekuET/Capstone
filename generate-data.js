// generate-data.js - Makes completely fake employees with the Faker library.
// Run once with: npm run generate   (overwrites fake-data.json)

const fs = require("fs");

const COMPANY = "Corvane Cloud Systems";        // fictional company
const DOMAIN = "corvane.example";         // change to your honeypot's domain if you like
const HOW_MANY = 25;

(async () => {
  const { faker } = await import("@faker-js/faker");
  faker.seed(2026); // same "random" people every time you run it

  const employees = [];
  for (let i = 0; i < HOW_MANY; i++) {
    const first = faker.person.firstName();
    const last = faker.person.lastName();
    const handle = (first[0] + last).toLowerCase().replace(/[^a-z]/g, "");

    employees.push({
      id: 1001 + i,
      name: first + " " + last,
      title: faker.person.jobTitle(),
      email: handle + "@" + DOMAIN,
      phone: "555-" + faker.string.numeric(3) + "-" + faker.string.numeric(4), // 555 = fictional numbers
      salary: faker.number.int({ min: 40, max: 110 }) * 1000
    });
  }

  fs.writeFileSync(__dirname + "/fake-data.json",
    JSON.stringify({ company: COMPANY, domain: DOMAIN, employees: employees }, null, 2));
  console.log("Wrote " + employees.length + " fake employees to fake-data.json");
})();
