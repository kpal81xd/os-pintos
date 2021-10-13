# configuration file for the Pintos exercise autotests

# docker local dirs
OUTPUT_DIRECTORY = "/root/results"
SKELETON_FILES = "/root/exercise/"
DEV_FILES = "/root/exercise/src"
JSON_INPUT_DATA = "/root/test_info.json"
CATE_TASK0_MILESTONE = 1 # need this to know which version of the tests to run

security = Unsecured.new
pdf_path = OUTPUT_DIRECTORY

# create the input engine
input = CIInput.new 

# create the engine modules

# code source engine
sf_engine = SourceFiles.new("Source Files", "{**/Makefile,**/*.h,**/*.c}", [], SKELETON_FILES, true)

# set up the test suite engine
json = File.open(JSON_INPUT_DATA,"r") do |file|
  JSON::parse(file.read, :symbolize_names=>true)
end
puts "JSON: #{json.inspect}"

milestone = json[:milestone]
task_num = milestone - CATE_TASK0_MILESTONE
task_num = 3 if json[:course] == "261C" 
test_engine = PintosTestEngine.new("Pintos autotest",DEV_FILES,task_num)

# create the output modules
dbug_output = DebugOutput.new

preview_output = PDFOutputter.new("Pintos Test Results - Preview") do |login, cls|
  File.join( pdf_path, "preview.pdf")
end

final_output = PDFOutputter.new("Pintos Test Results - Final") do |login, cls|
  File.join( pdf_path, "final.pdf")
end

ci_output = CIOutput.new

# setup a new LabCAT instance
lc = LabCAT.new(input, security)

# add modules
sf_engine_id = lc.add_engine(sf_engine)
test_engine_id = lc.add_engine(test_engine)
dbug_output_id = lc.add_output(dbug_output)
preview_output_id = lc.add_output(preview_output)
final_output_id = lc.add_output(final_output)
ci_output_id = lc.add_output(ci_output)

# link up the modules
lc.link_engine_output(test_engine_id, dbug_output_id)
lc.link_engine_output(test_engine_id, preview_output_id)
lc.link_engine_output(sf_engine_id, preview_output_id)
lc.link_engine_output(test_engine_id, final_output_id)
lc.link_engine_output(sf_engine_id, final_output_id)
lc.link_engine_output(test_engine_id, ci_output_id)

# print out the setup info
puts lc.describe

# fire it off
lc.run
