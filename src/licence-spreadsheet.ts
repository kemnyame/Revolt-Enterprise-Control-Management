import ExcelJS from 'exceljs';
import {Readable} from 'node:stream';
import {validateRecord} from './commercial-domain';
export const licenceHeaders=['SN','Software/Hardware/Service','Vendor','License Type','Department/Asset Owner/Users','Purchase Date / Last Renewal Date','Expiry / Renewal Date','Quantity Purchased','License / Seat Count','Quantity in Use','Status','Last Payment Date','Last Payment Amount (GHS)','ICDD Follow-up / Notes'];
const normal=(s:string)=>s.toLowerCase().replace(/[^a-z0-9]/g,'');
function value(cell:ExcelJS.Cell){const v:any=cell.value;if(v==null)return '';if(v instanceof Date)return v.toISOString().slice(0,10);if(typeof v==='object'){if(v.formula||v.sharedFormula)throw new Error('Paste values instead of spreadsheet formulas.');if(v.richText)return v.richText.map((x:any)=>x.text).join('');return String(v.text??v.result??'')}return String(v).trim()}
function dateValue(s:string){if(!s)return '';if(/^\d{4}-\d{2}-\d{2}$/.test(s))return s;const m=s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);if(m)return `${m[3]}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;if(/^\d{5}(\.\d+)?$/.test(s))return new Date(Date.UTC(1899,11,30)+Math.floor(Number(s))*86400000).toISOString().slice(0,10);return s}
export async function parseLicenceSpreadsheet(bytes:Buffer,name:string,owner:number){
 const wb=new ExcelJS.Workbook();let sheet:ExcelJS.Worksheet;
 if(name.toLowerCase().endsWith('.xlsx')){await wb.xlsx.load(bytes as any);sheet=wb.worksheets[0]}else if(name.toLowerCase().endsWith('.csv'))sheet=await wb.csv.read(Readable.from([bytes]));else throw new Error('Use an Excel .xlsx or CSV file.');
 if(!sheet||sheet.rowCount>1001)throw new Error('Use one worksheet with at most 1,000 data rows.');
 const headings=sheet.getRow(1).values as any[];if(licenceHeaders.some((h,i)=>normal(String(headings[i+1]||''))!==normal(h)))throw new Error('Use the original 14-column ICDD template in the same order.');
 const rows:any[]=[],errors:any[]=[];
 for(let i=2;i<=sheet.rowCount;i++){
  try{const cells=licenceHeaders.map((_,j)=>value(sheet.getRow(i).getCell(j+1)));if(cells.every(x=>!x))continue;
   const type=cells[3]||'Subscription';
   const row={title:cells[1],description:cells[13],owner_id:owner,priority:'Medium',status:cells[10],details:{sn:cells[0],vendor:cells[2],licence_type:type,department:cells[4],purchase_date:dateValue(cells[5]),expiry_date:dateValue(cells[6]),quantity_purchased:cells[7],seat_count:cells[8],quantity_in_use:cells[9],last_payment_date:dateValue(cells[11]),last_payment_amount:cells[12].replace(/,/g,''),notes:cells[13]}};
   validateRecord('licences',row);rows.push(row);
  }catch(e){errors.push({row:i,message:e instanceof Error?e.message:'This row could not be read.'})}
 }
 return {rows,errors,total:rows.length+errors.length};
}
export async function licenceTemplate(){const wb=new ExcelJS.Workbook(),sheet=wb.addWorksheet('ICDD Licences');sheet.addRow(licenceHeaders);sheet.getRow(1).font={bold:true};sheet.columns.forEach((c,i)=>c.width=[1,4,13].includes(i)?40:25);sheet.views=[{state:'frozen',ySplit:1}];return Buffer.from(await wb.xlsx.writeBuffer())}
