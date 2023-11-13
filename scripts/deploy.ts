import { ethers } from "hardhat";

async function main() {
  const attestor = await ethers.deployContract("RetrolistAttester", { nonce: 2 });
  await attestor.waitForDeployment();

  console.log("RetrolistAttester", await attestor.getAddress())
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
